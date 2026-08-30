<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\AuthzTables;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\TestCase;

/**
 * `dxs:seed-authz` — đối xứng với `dxs:sync-authz`: cùng một danh mục, một lệnh
 * đẩy LÊN Platform, một lệnh ghi XUỐNG bảng cục bộ.
 *
 * Seed là một lượt GHI vào DB, nên nó phải là một lệnh có người gọi tên — không
 * phải một tác dụng phụ của việc provider boot.
 */
final class SeedAuthzCommandTest extends TestCase
{
    use AuthzTables;

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('authz', [
            'permissions' => [['slug' => 'dashboard.view', 'display_name' => 'Dashboard · View', 'group' => 'dashboard']],
            'roles' => [['role' => 'staff', 'display_name' => 'Staff', 'level' => 10, 'permissions' => ['dashboard.view']]],
            'default_role' => 'staff',
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createAuthzTables();
    }

    protected function tearDown(): void
    {
        $this->dropAuthzTables();

        parent::tearDown();
    }

    public function test_it_seeds_the_catalog(): void
    {
        $this->artisan('dxs:seed-authz')
            ->expectsOutputToContain('1 permission(s), 1 role(s), 1 grant(s) created')
            ->assertSuccessful();

        $this->assertSame(1, DB::table('permissions')->count());
        $this->assertSame(1, DB::table('role_permissions')->count());
    }

    public function test_dry_run_writes_nothing(): void
    {
        $this->artisan('dxs:seed-authz', ['--dry-run' => true])
            ->expectsOutputToContain('dashboard.view')
            ->assertSuccessful();

        $this->assertSame(0, DB::table('permissions')->count());
    }

    public function test_an_empty_catalog_is_a_no_op(): void
    {
        config()->set('authz', ['permissions' => [], 'roles' => [], 'default_role' => null]);

        $this->artisan('dxs:seed-authz')
            ->expectsOutputToContain('nothing to seed')
            ->assertSuccessful();

        $this->assertSame(0, DB::table('permissions')->count());
    }

    public function test_an_invalid_catalog_fails_before_touching_the_database(): void
    {
        config()->set('authz', ['permissions' => [['slug' => 'ok'], ['slug' => 'ok']]]);

        $this->artisan('dxs:seed-authz')->assertFailed();

        $this->assertSame(0, DB::table('permissions')->count());
    }

    public function test_missing_tables_fail_the_command_instead_of_throwing(): void
    {
        $this->dropAuthzTables();

        $this->artisan('dxs:seed-authz')
            ->expectsOutputToContain('does not exist')
            ->assertFailed();
    }

    public function test_the_command_is_registered(): void
    {
        $this->assertArrayHasKey('dxs:seed-authz', $this->app[Kernel::class]->all());
    }
}
