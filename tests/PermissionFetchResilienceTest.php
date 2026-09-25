<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Facades\Sso;
use Dxs\Auth\Services\PermissionClient;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Orchestra\Testbench\TestCase;

/**
 * A transient platform outage during an authorization read must NOT hijack the
 * page: the renderable SsoException would 302 the whole response to the login
 * destination. Gate checks and the Sso facade fail CLOSED (log + deny) so a
 * brief outage denies gated actions rather than bouncing the user — unless
 * strict mode is on.
 */
final class PermissionFetchResilienceTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.permissions_path', 'api/sso/me/permissions');
        $app['config']->set('authz.permissions', [['slug' => 'branches.view']]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        Auth::setUser(new GenericUser(['password' => '', 
            'id' => 'user-1',
            'console_access_token' => 'at-1',
            'console_organization_id' => 'org-1',
        ]));
    }

    public function test_a_gate_check_denies_and_does_not_throw_when_the_platform_is_down(): void
    {
        $this->fakeOutage();
        Log::spy();

        // No exception bubbles up (which would 302 the page); the ability is denied.
        $this->assertFalse(Gate::forUser(Auth::user())->allows('branches.view'));
        Log::shouldHaveReceived('warning')->once();
    }

    public function test_the_facade_returns_empty_when_the_platform_is_down(): void
    {
        $this->fakeOutage();

        $this->assertTrue(Sso::permissions()->isEmpty());
        $this->assertSame([], Sso::roles());
        $this->assertFalse(Sso::can('branches.view'));
    }

    public function test_strict_mode_rethrows_so_outages_can_surface_loudly(): void
    {
        config()->set('sso.permissions.strict', true);
        $this->fakeOutage();

        $this->expectException(SsoException::class);

        $this->app->make(PermissionClient::class)->resolveFor('at-1', 'org-1');
    }

    public function test_the_raw_fetch_still_throws_for_callers_that_want_to_handle_it(): void
    {
        $this->fakeOutage();

        $this->expectException(SsoException::class);

        $this->app->make(PermissionClient::class)->fetch('at-1', 'org-1');
    }

    public function test_recovery_after_an_outage_resolves_permissions_again(): void
    {
        // First read hits an outage (not cached), the second recovers.
        Http::fake([
            'https://id.example.test/api/sso/me/permissions*' => Http::sequence()
                ->push('platform down', 503)
                ->push(['permissions' => ['branches.view'], 'roles' => [], 'authoritative' => true], 200),
        ]);

        $this->assertFalse(Sso::can('branches.view'));
        $this->assertTrue(Sso::can('branches.view'));
    }

    public function test_malformed_permission_contracts_fail_closed_without_a_type_error(): void
    {
        Http::fake([
            '*' => Http::response([
                'permissions' => 'branches.view',
                'roles' => ['manager'],
                'authoritative' => true,
            ]),
        ]);
        Log::spy();

        $this->assertFalse(Gate::forUser(Auth::user())->allows('branches.view'));
        $this->assertFalse(Sso::hasRole('manager'));
        Log::shouldHaveReceived('warning')->twice();
    }

    private function fakeOutage(): void
    {
        Http::fake([
            'https://id.example.test/api/sso/me/permissions*' => Http::response('platform down', 503),
        ]);
    }
}
