<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Services\JwtVerifier;
use Dxs\Auth\Services\LogoutSessionRegistry;
use Dxs\Auth\Services\OidcDiscovery;
use Dxs\Auth\Services\PermissionClient;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Support\SsoCache;
use Dxs\Auth\Tests\Support\JwtFactory;
use Illuminate\Auth\GenericUser;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * The cache/sync processes are plain Laravel cache + scheduler, driven by
 * config: the package uses the app's default cache store (redis, file,
 * whatever the downstream picked) unless `sso.cache.store` points elsewhere;
 * JWKS gets its own TTL; revoked bearers lose their cached permission lists;
 * and the authz catalog can sync itself on the scheduler, skipping when
 * nothing changed.
 */
final class CacheAndSyncConfigurationTest extends TestCase
{
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
        $app['config']->set('cache.stores.sso-isolated', ['driver' => 'array']);
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.client_secret', 'consumer-a-secret');
        $app['config']->set('sso.permissions_path', 'api/sso/me/permissions');
        $app['config']->set('sso.service_id', 'consumer-a');
        $app['config']->set('sso.admin_token', 'admin-secret');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        Cache::store('sso-isolated')->flush();
        $this->jwt = new JwtFactory;
        $this->app->instance(ProvisionsUsers::class, new NoopProvisioner);
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        parent::tearDown();
    }

    // ---- store & prefix ---------------------------------------------------

    public function test_by_default_the_package_rides_the_apps_default_laravel_cache(): void
    {
        $this->fakeIdp();
        $this->app->make(OidcDiscovery::class)->authorizationEndpoint();

        // Flushing the DEFAULT store forces a refetch → it was cached there.
        Cache::flush();
        $this->app->make(OidcDiscovery::class)->authorizationEndpoint();

        $this->assertSame(2, $this->requestCount('openid-configuration'));
    }

    public function test_the_cache_store_and_prefix_are_configurable(): void
    {
        config()->set('sso.cache.store', 'sso-isolated');
        config()->set('sso.cache.prefix', 'acme');

        $this->assertSame('acme:x', SsoCache::key('x'));

        $this->fakeIdp();
        $this->app->make(OidcDiscovery::class)->authorizationEndpoint();

        // Flushing the app default store must NOT evict the package cache…
        Cache::flush();
        $this->app->make(OidcDiscovery::class)->authorizationEndpoint();
        $this->assertSame(1, $this->requestCount('openid-configuration'));

        // …but flushing the configured store does.
        Cache::store('sso-isolated')->flush();
        $this->app->make(OidcDiscovery::class)->authorizationEndpoint();
        $this->assertSame(2, $this->requestCount('openid-configuration'));
    }

    public function test_jwks_rotates_on_its_own_ttl_independent_of_discovery(): void
    {
        config()->set('sso.discovery_ttl', 3600);
        config()->set('sso.cache.jwks_ttl', 60);
        $this->fakeIdp();

        $verifier = $this->app->make(JwtVerifier::class);
        $verifier->verify($this->jwt->token());
        Carbon::setTestNow(now()->addSeconds(120));
        $verifier->verify($this->jwt->token());

        $this->assertSame(2, $this->requestCount('jwks.json'));
        $this->assertSame(1, $this->requestCount('openid-configuration'));
    }

    // ---- invalidation -----------------------------------------------------

    public function test_backchannel_logout_busts_the_revoked_bearers_permission_cache(): void
    {
        $this->fakeIdp();
        $bearer = $this->jwt->token();
        $client = $this->app->make(PermissionClient::class);

        $client->fetch($bearer, 'org-1');
        $client->fetch($bearer, 'org-1');
        $this->assertSame(1, $this->requestCount('permissions'));

        $this->app->make(LogoutSessionRegistry::class)
            ->register(['sid' => 'sid-1', 'exp' => time() + 900], $bearer, 'session-1');

        $logoutToken = $this->jwt->token([
            'aud' => 'consumer-a-client',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => (object) []],
            'jti' => 'jti-1',
            'sid' => 'sid-1',
        ]);
        $this->post('/auth/backchannel-logout', ['logout_token' => $logoutToken])->assertOk();

        $client->fetch($bearer, 'org-1');
        $this->assertSame(2, $this->requestCount('permissions'));
    }

    public function test_local_logout_busts_the_cookie_bearers_permission_cache(): void
    {
        $this->fakeIdp();
        $bearer = $this->jwt->token();
        $client = $this->app->make(PermissionClient::class);

        $client->fetch($bearer, 'org-1');
        $this->assertSame(1, $this->requestCount('permissions'));

        $this->withCookie('token', $bearer)->post('/auth/logout');

        $client->fetch($bearer, 'org-1');
        $this->assertSame(2, $this->requestCount('permissions'));
    }

    // ---- authz sync -------------------------------------------------------

    public function test_if_changed_sync_skips_until_the_catalog_actually_changes(): void
    {
        config()->set('authz', $this->catalog(['consumer.read']));
        Http::fake(['https://id.example.test/*' => Http::response(['ok' => true])]);

        $this->artisan('dxs:sync-authz --if-changed')->assertExitCode(0);
        $this->artisan('dxs:sync-authz --if-changed')
            ->expectsOutputToContain('unchanged')
            ->assertExitCode(0);
        $this->assertSame(1, count(Http::recorded()));

        config()->set('authz', $this->catalog(['consumer.read', 'consumer.write']));
        $this->artisan('dxs:sync-authz --if-changed')->assertExitCode(0);
        $this->assertSame(2, count(Http::recorded()));
    }

    public function test_the_scheduler_picks_up_the_sync_when_enabled(): void
    {
        config()->set('sso.sync.authz.auto', true);
        config()->set('sso.sync.authz.schedule', 'hourly');

        $events = collect($this->app->make(Schedule::class)->events());
        $event = $events->first(fn ($candidate) => str_contains((string) $candidate->command, 'dxs:sync-authz'));

        $this->assertNotNull($event, 'The sync command must be scheduled.');
        $this->assertStringContainsString('--if-changed', (string) $event->command);
        $this->assertSame('0 * * * *', $event->expression);
    }

    public function test_a_cron_expression_schedule_is_honoured(): void
    {
        config()->set('sso.sync.authz.auto', true);
        config()->set('sso.sync.authz.schedule', '15 3 * * *');

        $event = collect($this->app->make(Schedule::class)->events())
            ->first(fn ($candidate) => str_contains((string) $candidate->command, 'dxs:sync-authz'));

        $this->assertSame('15 3 * * *', $event->expression);
    }

    public function test_the_sync_stays_off_the_scheduler_by_default(): void
    {
        $events = collect($this->app->make(Schedule::class)->events())
            ->filter(fn ($candidate) => str_contains((string) $candidate->command, 'dxs:sync-authz'));

        $this->assertCount(0, $events);
    }

    // ---- helpers ----------------------------------------------------------

    /** @param list<string> $slugs */
    private function catalog(array $slugs): array
    {
        return [
            'permissions' => array_map(fn (string $slug): array => ['slug' => $slug], $slugs),
            'roles' => [['role' => 'member', 'permissions' => $slugs]],
            'default_role' => 'member',
        ];
    }

    private function fakeIdp(): void
    {
        Http::fake(function (ClientRequest $request) {
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
            if (str_contains($request->url(), 'permissions')) {
                return Http::response(['permissions' => ['x.view'], 'roles' => [], 'authoritative' => true]);
            }

            return Http::response(['ok' => true]);
        });
    }

    private function requestCount(string $needle): int
    {
        return collect(Http::recorded())
            ->filter(fn (array $pair): bool => str_contains($pair[0]->url(), $needle))
            ->count();
    }
}

final class NoopProvisioner implements ProvisionsUsers
{
    public function provision(array $claims, array $tokens): Authenticatable
    {
        return new GenericUser(['password' => '', 'id' => $claims['sub'] ?? 'user']);
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        return null;
    }
}
