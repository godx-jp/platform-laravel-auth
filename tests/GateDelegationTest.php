<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * The provider's Gate::before hook — authorization DECISIONS stay on the
 * platform. A granted ability is one present in the user's platform-resolved
 * permission list; anything else falls through (null) so local policies still
 * apply, and users without platform context never consult the platform.
 */
final class GateDelegationTest extends TestCase
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
        $app['config']->set('sso.permissions_ttl', 300);
        $app['config']->set('authz.permissions', [
            ['slug' => 'dashboard.view'],
            ['slug' => 'employees.view'],
            ['slug' => 'employees.delete'],
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
    }

    public function test_an_ability_in_the_platform_permission_list_is_granted(): void
    {
        $this->fakePermissions(['dashboard.view', 'employees.view']);

        $this->assertTrue(Gate::forUser($this->platformUser())->allows('dashboard.view'));
        $this->assertTrue(Gate::forUser($this->platformUser())->allows('employees.view'));
    }

    public function test_an_ability_missing_from_the_list_is_denied_when_no_local_policy_exists(): void
    {
        $this->fakePermissions(['dashboard.view']);

        $this->assertFalse(Gate::forUser($this->platformUser())->allows('employees.delete'));
    }

    public function test_local_gate_definitions_still_run_for_abilities_outside_the_list(): void
    {
        $this->fakePermissions(['dashboard.view']);
        Gate::define('local.feature', fn ($user): bool => true);

        $this->assertTrue(Gate::forUser($this->platformUser())->allows('local.feature'));
    }

    public function test_the_platform_list_cannot_be_vetoed_downward_by_a_local_definition(): void
    {
        $this->fakePermissions(['dashboard.view']);
        Gate::define('dashboard.view', fn ($user): bool => false);

        // Gate::before returning true short-circuits the local definition.
        $this->assertTrue(Gate::forUser($this->platformUser())->allows('dashboard.view'));
    }

    public function test_a_user_without_platform_context_never_contacts_the_platform(): void
    {
        Http::fake();

        $localUser = new GenericUser(['id' => 'local-1']);

        $this->assertFalse(Gate::forUser($localUser)->allows('dashboard.view'));
        Http::assertNothingSent();
    }

    public function test_the_permission_list_is_fetched_once_per_context_within_the_ttl(): void
    {
        $this->fakePermissions(['dashboard.view']);

        $user = $this->platformUser();
        Gate::forUser($user)->allows('dashboard.view');
        Gate::forUser($user)->allows('employees.view');
        Gate::forUser($user)->allows('dashboard.view');

        Http::assertSentCount(1);
    }

    private function platformUser(): GenericUser
    {
        return new GenericUser([
            'id' => 'user-1',
            'console_access_token' => 'platform-access-token',
            'console_organization_id' => 'org-1',
        ]);
    }

    /** @param list<string> $permissions */
    private function fakePermissions(array $permissions): void
    {
        Http::fake([
            'https://id.example.test/api/sso/me/permissions*' => Http::response([
                'permissions' => $permissions,
                'roles' => [],
                'authoritative' => true,
            ]),
        ]);
    }

    public function test_a_non_authoritative_read_model_cannot_grant_a_declared_ability(): void
    {
        Http::fake([
            '*' => Http::response([
                'permissions' => ['dashboard.view'],
                'roles' => [],
                'authoritative' => false,
            ]),
        ]);
        Gate::define('dashboard.view', fn (): bool => true);

        $this->assertFalse(Gate::forUser($this->platformUser())->allows('dashboard.view'));
    }
}
