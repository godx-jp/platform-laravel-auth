<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Events\SsoAuthenticated;
use Dxs\Auth\Events\SsoLoggedOut;
use Dxs\Auth\Facades\Sso;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\JwtFactory;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * The read surface (Sso facade → SsoManager) and lifecycle events that let a
 * downstream app act on login/logout without touching the HTTP client.
 */
final class SsoManagerAndEventsTest extends TestCase
{
    private const ORG_ID = '019f6ece-2629-730a-ab0b-0f323d4e2e02';

    private JwtFactory $jwt;

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
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.client_secret', 'consumer-a-secret');
        $app['config']->set('sso.redirect_uri', 'https://consumer-a.example.test/auth/callback');
        $app['config']->set('sso.after_login', '/home');
        $app['config']->set('sso.after_logout', '/bye');
        $app['config']->set('sso.permissions_path', 'api/sso/me/permissions');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        $this->jwt = new JwtFactory;
        $this->app->instance(ProvisionsUsers::class, new RecordingDirectory);
    }

    // ---- SsoManager / Sso facade -----------------------------------------

    public function test_an_unauthenticated_visitor_has_no_permissions_and_no_platform_calls(): void
    {
        Http::fake();

        $this->assertFalse(Sso::check());
        $this->assertTrue(Sso::permissions()->isEmpty());
        $this->assertSame([], Sso::roles());
        $this->assertFalse(Sso::can('anything'));
        Http::assertNothingSent();
    }

    public function test_the_facade_exposes_the_current_users_platform_permissions_and_roles(): void
    {
        $this->actingAsPlatformUser(
            ['branches.view', 'branches.create'],
            [['role' => 'manager', 'display_name' => 'Manager', 'level' => 50]],
        );

        $this->assertTrue(Sso::check());
        $this->assertEqualsCanonicalizing(['branches.view', 'branches.create'], Sso::permissions()->all());
        $this->assertSame('manager', Sso::roles()[0]['role']);

        $this->assertTrue(Sso::can('branches.view'));
        $this->assertFalse(Sso::can('branches.delete'));
        $this->assertTrue(Sso::canAll('branches.view', 'branches.create'));
        $this->assertFalse(Sso::canAll('branches.view', 'branches.delete'));
        $this->assertTrue(Sso::canAny('branches.delete', 'branches.view'));
        $this->assertFalse(Sso::canAny('branches.delete', 'branches.archive'));
        $this->assertTrue(Sso::hasRole('manager'));
        $this->assertFalse(Sso::hasRole('admin'));
    }

    public function test_the_facade_exposes_service_access_and_tenant_directory_without_exposing_the_token(): void
    {
        Http::fake([
            'https://id.example.test/api/sso/me/permissions*' => Http::response([
                'permissions' => ['branches.view'],
                'roles' => ['manager'],
                'service_access' => ['consumer-a' => ['role' => 'manager']],
                'authoritative' => true,
            ]),
            'https://id.example.test/api/sso/organizations' => Http::response([
                ['organization_id' => self::ORG_ID, 'organization_slug' => 'acme'],
            ]),
            'https://id.example.test/api/sso/access*' => Http::response(['service_role' => 'manager']),
            'https://id.example.test/api/sso/branches*' => Http::response(['branches' => [['id' => 'branch-1']]]),
            'https://id.example.test/api/sso/brands*' => Http::response(['brands' => [['brand_id' => 'brand-1']]]),
            'https://id.example.test/api/sso/teams*' => Http::response(['teams' => [['id' => 'team-1']]]),
        ]);

        Auth::setUser(new GenericUser([
            'id' => 'user-1',
            'console_access_token' => 'at-private',
            'console_organization_id' => self::ORG_ID,
        ]));

        $this->assertSame('manager', Sso::serviceAccess()['consumer-a']['role']);
        $this->assertSame('acme', Sso::organizations()[0]['organization_slug']);
        $this->assertSame('manager', Sso::organizationAccess('acme')['service_role']);
        $this->assertSame('branch-1', Sso::branches('acme')['branches'][0]['id']);
        $this->assertSame('brand-1', Sso::brands('acme')['brands'][0]['brand_id']);
        $this->assertSame('team-1', Sso::teams('acme')['teams'][0]['id']);
    }

    public function test_the_facade_reuses_the_gate_permission_cache_no_extra_platform_calls(): void
    {
        $this->actingAsPlatformUser(['x.view'], []);

        Sso::permissions();
        Sso::roles();
        Sso::can('x.view');

        $calls = collect(Http::recorded())
            ->filter(fn (array $pair): bool => str_contains($pair[0]->url(), 'permissions'))
            ->count();

        $this->assertSame(1, $calls);
    }

    public function test_has_role_accepts_the_platform_string_role_contract(): void
    {
        $this->actingAsPlatformUser(['branches.view'], ['manager']);

        $this->assertTrue(Sso::hasRole('manager'));
        $this->assertFalse(Sso::hasRole('admin'));
    }

    public function test_has_role_cannot_authorize_from_a_non_authoritative_read_model(): void
    {
        Http::fake([
            '*' => Http::response([
                'permissions' => [],
                'roles' => ['manager'],
                'authoritative' => false,
            ]),
        ]);
        Auth::setUser(new GenericUser([
            'id' => 'user-1',
            'console_access_token' => 'at-1',
            'console_organization_id' => self::ORG_ID,
        ]));

        $this->assertFalse(Sso::hasRole('manager'));
    }

    public function test_a_user_without_platform_context_is_treated_as_unauthenticated_for_permissions(): void
    {
        Http::fake();
        Auth::setUser(new GenericUser(['id' => 'local-only']));

        $this->assertFalse(Sso::check());
        $this->assertTrue(Sso::permissions()->isEmpty());
        Http::assertNothingSent();
    }

    // ---- Events -----------------------------------------------------------

    public function test_a_successful_callback_dispatches_sso_authenticated_with_first_login_true(): void
    {
        Event::fake([SsoAuthenticated::class]);
        $this->fakeCallbackIdp();

        $this->withSession($this->boundSession())
            ->get('/auth/callback?code=authorization-code&state=bound-state')
            ->assertRedirect('/home');

        Event::assertDispatched(SsoAuthenticated::class, function (SsoAuthenticated $event): bool {
            return $event->firstLogin === true
                && $event->claims['sub'] === 'user-1'
                && data_get($event->user, 'id') === 'user-1';
        });
    }

    public function test_a_returning_user_dispatches_sso_authenticated_with_first_login_false(): void
    {
        // Seed the directory so resolveBySubject finds the user before provisioning.
        $this->app->make(ProvisionsUsers::class)->provision(['sub' => 'user-1'], ['access_token' => 'seed']);

        Event::fake([SsoAuthenticated::class]);
        $this->fakeCallbackIdp();

        $this->withSession($this->boundSession())
            ->get('/auth/callback?code=authorization-code&state=bound-state')
            ->assertRedirect('/home');

        Event::assertDispatched(SsoAuthenticated::class, fn (SsoAuthenticated $event): bool => $event->firstLogin === false);
    }

    public function test_logout_dispatches_sso_logged_out_with_the_outgoing_user(): void
    {
        Event::fake([SsoLoggedOut::class]);
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
        ]);

        $user = new GenericUser(['id' => 'user-1']);
        $this->actingAs($user)->post('/auth/logout');

        Event::assertDispatched(SsoLoggedOut::class, fn (SsoLoggedOut $event): bool => data_get($event->user, 'id') === 'user-1');
    }

    // ---- helpers ----------------------------------------------------------

    /**
     * @param  list<string>  $permissions
     * @param  list<array<string, mixed>>  $roles
     */
    private function actingAsPlatformUser(array $permissions, array $roles): void
    {
        Http::fake([
            'https://id.example.test/api/sso/me/permissions*' => Http::response([
                'permissions' => $permissions,
                'roles' => $roles,
                'authoritative' => true,
            ]),
        ]);

        Auth::setUser(new GenericUser([
            'id' => 'user-1',
            'console_access_token' => 'at-1',
            'console_organization_id' => self::ORG_ID,
        ]));
    }

    /** @return array<string, mixed> */
    private function boundSession(): array
    {
        return [
            'sso.transactions' => [
                'bound-state' => [
                    'verifier' => 'v',
                    'nonce' => 'bound-nonce',
                    'organization_context_id' => self::ORG_ID,
                    'return' => null,
                    'created_at' => now()->timestamp,
                ],
            ],
        ];
    }

    private function fakeCallbackIdp(): void
    {
        $accessToken = $this->jwt->token(['organization_context_id' => self::ORG_ID]);
        $idToken = $this->jwt->idToken(['nonce' => 'bound-nonce']);

        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
            'https://id.example.test/api/sso/token' => Http::response([
                'access_token' => $accessToken,
                'id_token' => $idToken,
                'token_type' => 'Bearer',
                'expires_in' => 900,
            ]),
            'https://id.example.test/.well-known/jwks.json' => Http::response($this->jwt->jwks()),
        ]);
    }
}

final class RecordingDirectory implements ProvisionsUsers
{
    /** @var array<string, GenericUser> */
    private array $users = [];

    public function provision(array $claims, array $tokens): Authenticatable
    {
        $subject = (string) $claims['sub'];

        return $this->users[$subject] = new GenericUser([
            'id' => $subject,
            'console_access_token' => $tokens['access_token'] ?? null,
        ]);
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        return $this->users[$subject] ?? null;
    }
}
