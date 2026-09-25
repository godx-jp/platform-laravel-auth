<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\JwtFactory;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * The package-owned `sso.can:{ability}` gate: one alias that authenticates the
 * platform bearer and requires the listed abilities, denying with RFC 6750
 * §3.1 `insufficient_scope` semantics so clients can tell "bad token" (401,
 * invalid_token) from "good token, missing permission" (403) by header alone.
 */
final class AuthorizeSsoPermissionMiddlewareTest extends TestCase
{
    private const ORG_ID = '019f6ece-2629-730a-ab0b-0f323d4e2e02';

    private JwtFactory $jwt;

    private string $managerToken;

    private string $viewerToken;

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['env'] = 'production';
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('session.driver', 'array');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.permissions_path', 'api/sso/me/permissions');
        $app['config']->set('authz.permissions', [
            ['slug' => 'branches.view'],
            ['slug' => 'branches.create'],
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
        $this->jwt = new JwtFactory;
        $this->app->instance(ProvisionsUsers::class, new SubjectDirectory);

        $this->managerToken = $this->jwt->token(['sub' => 'manager', 'organization_id' => self::ORG_ID]);
        $this->viewerToken = $this->jwt->token(['sub' => 'viewer', 'organization_id' => self::ORG_ID]);

        $router = $this->app['router'];
        $router->get('/api/branches', fn () => response()->json(['ok' => true]))
            ->middleware('sso.can:branches.view');
        $router->post('/api/branches', fn () => response()->json(['ok' => true], 201))
            ->middleware('sso.can:branches.view,branches.create');
        $router->get('/api/local-tool', fn () => response()->json(['ok' => true]))
            ->middleware('sso.can:local.tool');

        $this->fakePlatform();
    }

    public function test_one_alias_authenticates_and_authorizes_in_a_single_hop(): void
    {
        $this->withHeader('Authorization', 'Bearer '.$this->viewerToken)
            ->getJson('/api/branches')
            ->assertOk();
    }

    public function test_multiple_abilities_are_all_required(): void
    {
        $this->withHeader('Authorization', 'Bearer '.$this->managerToken)
            ->postJson('/api/branches', [])
            ->assertCreated();

        $this->withHeader('Authorization', 'Bearer '.$this->viewerToken)
            ->postJson('/api/branches', [])
            ->assertForbidden();
    }

    public function test_a_denial_speaks_rfc_6750_insufficient_scope_and_names_the_missing_ability(): void
    {
        $this->withHeader('Authorization', 'Bearer '.$this->viewerToken)
            ->postJson('/api/branches', [])
            ->assertForbidden()
            ->assertHeader('WWW-Authenticate', 'Bearer realm="sso", error="insufficient_scope", scope="branches.create"')
            ->assertJsonPath('required_permission', 'branches.create');
    }

    public function test_a_missing_token_is_still_401_invalid_token_semantics_not_403(): void
    {
        $this->getJson('/api/branches')
            ->assertUnauthorized()
            ->assertHeader('WWW-Authenticate', 'Bearer realm="sso"');
    }

    public function test_local_gate_definitions_still_answer_abilities_outside_the_platform_list(): void
    {
        Gate::define('local.tool', fn ($user): bool => $user->id === 'viewer');

        $this->withHeader('Authorization', 'Bearer '.$this->viewerToken)
            ->getJson('/api/local-tool')
            ->assertOk();

        $this->withHeader('Authorization', 'Bearer '.$this->managerToken)
            ->getJson('/api/local-tool')
            ->assertForbidden();
    }

    private function fakePlatform(): void
    {
        $permissions = [
            $this->managerToken => ['branches.view', 'branches.create'],
            $this->viewerToken => ['branches.view'],
        ];

        Http::fake(function (ClientRequest $request) use ($permissions) {
            if (str_contains($request->url(), 'openid-configuration')) {
                return Http::response([
                    'issuer' => 'https://id.example.test',
                    'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                    'token_endpoint' => 'https://id.example.test/api/sso/token',
                    'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
                ]);
            }
            if (str_contains($request->url(), 'jwks.json')) {
                return Http::response($this->jwt->jwks());
            }
            if (str_contains($request->url(), 'api/sso/me/permissions')) {
                $token = str_replace('Bearer ', '', (string) $request->header('Authorization')[0]);

                return Http::response([
                    'permissions' => $permissions[$token] ?? [],
                    'roles' => [],
                    'authoritative' => true,
                ]);
            }

            return Http::response([], 500);
        });
    }
}

final class SubjectDirectory implements ProvisionsUsers
{
    /** @var array<string, GenericUser> */
    private array $users = [];

    public function provision(array $claims, array $tokens): Authenticatable
    {
        $subject = (string) $claims['sub'];

        return $this->users[$subject] = new GenericUser(['password' => '', 
            'id' => $subject,
            'console_access_token' => $tokens['access_token'] ?? null,
            'console_organization_id' => $claims['organization_id'] ?? null,
        ]);
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        return $this->users[$subject] ?? null;
    }
}
