<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Services\LogoutSessionRegistry;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\JwtFactory;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class AuthenticateSsoMiddlewareTest extends TestCase
{
    private JwtFactory $jwt;

    private MiddlewareProvisioner $provisioner;

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('session.driver', 'array');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
    }

    protected function defineRoutes($router): void
    {
        $router->get('/protected', function (): array {
            return [
                'subject' => request()->attributes->get('sso_subject'),
                'claims' => request()->attributes->get('sso_claims'),
                'user' => request()->user()?->getAuthIdentifier(),
            ];
        })->middleware('sso.auth');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
        $this->jwt = new JwtFactory;
        $this->provisioner = new MiddlewareProvisioner;
        $this->app->instance(ProvisionsUsers::class, $this->provisioner);
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
            'https://id.example.test/.well-known/jwks.json' => Http::response($this->jwt->jwks()),
        ]);
    }

    public function test_it_authenticates_a_valid_bearer_and_exposes_only_verified_identity(): void
    {
        $response = $this->withToken($this->jwt->token())->getJson('/protected');

        $response->assertSuccessful()
            ->assertJsonPath('subject', 'user-1')
            ->assertJsonPath('claims.sub', 'user-1')
            ->assertJsonPath('user', 'user-1');
        $this->assertSame(1, $this->provisioner->provisionCalls);
    }

    public function test_a_valid_bearer_does_not_resolve_the_session_provider_first(): void
    {
        Auth::shouldReceive('check')->never();
        Auth::shouldReceive('setUser')->once()->withArgs(
            fn (Authenticatable $user): bool => $user->getAuthIdentifier() === 'user-1',
        );

        $this->withToken($this->jwt->token())
            ->getJson('/protected')
            ->assertSuccessful()
            ->assertJsonPath('subject', 'user-1')
            ->assertJsonPath('user', 'user-1');
    }

    public function test_it_reuses_an_existing_local_user_without_reprovisioning(): void
    {
        $this->provisioner->existingUser = new GenericUser(['password' => '', 'id' => 'user-1']);

        $this->withToken($this->jwt->token())->getJson('/protected')->assertSuccessful();

        $this->assertSame(0, $this->provisioner->provisionCalls);
    }

    public function test_missing_or_invalid_bearers_fail_closed_for_json_requests(): void
    {
        $this->getJson('/protected')->assertUnauthorized()->assertJsonPath('message', 'Unauthenticated.');
        $this->withToken('not-a-jwt')->getJson('/protected')
            ->assertUnauthorized()
            ->assertJsonPath('message', 'Unauthenticated.');
        $this->assertSame(0, $this->provisioner->provisionCalls);
    }

    public function test_a_bearer_revoked_by_back_channel_session_lineage_fails_closed(): void
    {
        $token = $this->jwt->token(['sid' => 'revoked-lineage']);
        $registry = $this->app->make(LogoutSessionRegistry::class);
        $registry->register(['sid' => 'revoked-lineage', 'exp' => time() + 300], $token, 'session-1');
        $registry->revoke('revoked-lineage');

        $this->withToken($token)->getJson('/protected')->assertUnauthorized();
        $this->assertSame(0, $this->provisioner->provisionCalls);
    }

    public function test_an_html_request_redirects_with_a_local_relative_return_path(): void
    {
        $response = $this->get('/protected?tab=security');

        $response->assertRedirect();
        $location = (string) $response->headers->get('Location');
        $this->assertStringContainsString('/auth/redirect?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame('/protected?tab=security', $query['return']);
    }
}

final class MiddlewareProvisioner implements ProvisionsUsers
{
    public ?Authenticatable $existingUser = null;

    public int $provisionCalls = 0;

    public function provision(array $claims, array $tokens): Authenticatable
    {
        $this->provisionCalls++;

        return new GenericUser(['password' => '', 'id' => $claims['sub']]);
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        return $this->existingUser;
    }
}
