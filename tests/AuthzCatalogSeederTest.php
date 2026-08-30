<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Database\Seeders\AuthzCatalogSeeder;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\AuthzTables;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\TestCase;
use RuntimeException;

/**
 * Thay đổi phá vỡ số 3 của 1.0.0: package tự seed bảng `permissions` + vai toàn
 * hệ thống + cặp nối, với guard `wasRecentlyCreated`.
 *
 * Bài quan trọng nhất ở đây là {@see self::test_a_revoked_grant_is_not_restored_on_reseed()}.
 * Nó là lý do guard tồn tại: `sync()` sẽ cấp lại đúng cái quyền tổ chức vừa gỡ,
 * mỗi lần deploy, không một dòng log.
 */
final class AuthzCatalogSeederTest extends TestCase
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
            'permissions' => [
                ['slug' => 'dashboard.view', 'display_name' => 'Dashboard · View', 'group' => 'dashboard'],
                ['slug' => 'employees.delete', 'display_name' => 'Employees · Delete', 'group' => 'employees'],
            ],
            'roles' => [
                ['role' => 'staff', 'display_name' => 'Staff', 'level' => 10, 'permissions' => ['dashboard.view']],
                ['role' => 'admin', 'display_name' => 'Administrator', 'level' => 100, 'permissions' => ['dashboard.view', 'employees.delete']],
            ],
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

    private function seeder(): AuthzCatalogSeeder
    {
        return $this->app->make(AuthzCatalogSeeder::class);
    }

    public function test_it_seeds_permissions_roles_and_grants_from_the_catalog(): void
    {
        $result = $this->seeder()->seed();

        $this->assertSame(2, $result['permissions_created']);
        $this->assertSame(2, $result['roles_created']);
        $this->assertSame(3, $result['grants_created']);

        $this->assertSame(
            ['dashboard.view', 'employees.delete'],
            DB::table('permissions')->orderBy('slug')->pluck('slug')->all(),
        );
        $this->assertSame('dashboard', DB::table('permissions')->where('slug', 'dashboard.view')->value('group'));
        $this->assertSame('Dashboard · View', DB::table('permissions')->where('slug', 'dashboard.view')->value('name'));

        // Vai của package là vai TOÀN HỆ THỐNG — không thuộc tổ chức nào.
        $this->assertNull(DB::table('roles')->where('slug', 'staff')->value('console_organization_id'));
        $this->assertSame(100, (int) DB::table('roles')->where('slug', 'admin')->value('level'));

        $this->assertSame(1, $this->grantCount('staff'));
        $this->assertSame(2, $this->grantCount('admin'));
    }

    public function test_re_seeding_creates_nothing_new(): void
    {
        $this->seeder()->seed();
        $result = $this->seeder()->seed();

        $this->assertSame(
            ['permissions_created' => 0, 'roles_created' => 0, 'grants_created' => 0],
            $result,
        );
        $this->assertSame(2, DB::table('permissions')->count());
        $this->assertSame(2, DB::table('roles')->count());
        $this->assertSame(3, DB::table('role_permissions')->count());
    }

    public function test_a_revoked_grant_is_not_restored_on_reseed(): void
    {
        $this->seeder()->seed();

        // Tổ chức gỡ một quyền khỏi vai admin qua màn hình IAM của họ.
        $adminId = DB::table('roles')->where('slug', 'admin')->value('id');
        $permissionId = DB::table('permissions')->where('slug', 'employees.delete')->value('id');
        DB::table('role_permissions')->where('role_id', $adminId)->where('permission_id', $permissionId)->delete();

        $result = $this->seeder()->seed();

        $this->assertSame(0, $result['grants_created']);
        $this->assertSame(1, $this->grantCount('admin'), 'Seeder re-applied a grant the organization had revoked.');
    }

    public function test_a_slug_added_to_the_catalog_later_is_created_and_granted(): void
    {
        $this->seeder()->seed();

        $catalog = config('authz');
        $catalog['permissions'][] = ['slug' => 'reports.view', 'display_name' => 'Reports · View', 'group' => 'reports'];
        $catalog['roles'][1]['permissions'][] = 'reports.view';
        config()->set('authz', $catalog);

        $result = $this->seeder()->seed();

        $this->assertSame(1, $result['permissions_created']);
        $this->assertSame(0, $result['roles_created']);
        $this->assertSame(1, $result['grants_created']);
        $this->assertSame(3, $this->grantCount('admin'));
    }

    public function test_a_role_added_later_receives_its_grants_even_for_pre_existing_slugs(): void
    {
        $this->seeder()->seed();

        // Vai mới toanh: tổ chức chưa từng thấy nó, nên chưa từng có ý kiến gì
        // về quyền của nó. Chỉ dựa vào `wasRecentlyCreated` của PERMISSION thì
        // vai này ra đời RỖNG, im lặng.
        $catalog = config('authz');
        $catalog['roles'][] = ['role' => 'auditor', 'display_name' => 'Auditor', 'level' => 50, 'permissions' => ['dashboard.view']];
        config()->set('authz', $catalog);

        $result = $this->seeder()->seed();

        $this->assertSame(0, $result['permissions_created']);
        $this->assertSame(1, $result['roles_created']);
        $this->assertSame(1, $result['grants_created']);
        $this->assertSame(1, $this->grantCount('auditor'));
    }

    public function test_it_never_deletes_a_grant_the_catalog_no_longer_declares(): void
    {
        $this->seeder()->seed();

        $catalog = config('authz');
        $catalog['roles'][1]['permissions'] = ['dashboard.view'];
        config()->set('authz', $catalog);

        $this->seeder()->seed();

        // Gỡ quyền là việc của tổ chức, không phải của seeder.
        $this->assertSame(2, $this->grantCount('admin'));
    }

    public function test_an_invalid_catalog_stops_before_writing_anything(): void
    {
        config()->set('authz', ['permissions' => [['slug' => 'Invalid Slug']]]);

        $this->expectException(RuntimeException::class);

        try {
            $this->seeder()->seed();
        } finally {
            $this->assertSame(0, DB::table('permissions')->count());
        }
    }

    public function test_missing_tables_are_reported_not_swallowed(): void
    {
        $this->dropAuthzTables();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/does not exist/');

        $this->seeder()->seed();
    }

    public function test_pending_slugs_reports_what_a_seed_would_create(): void
    {
        $this->assertSame(['dashboard.view', 'employees.delete'], $this->seeder()->pendingSlugs());

        $this->seeder()->seed();

        $this->assertSame([], $this->seeder()->pendingSlugs());
    }

    public function test_a_pivot_with_a_uuid_primary_key_is_filled_in(): void
    {
        $this->dropAuthzTables();
        $this->createAuthzTables(pivotKey: 'uuid');

        $this->seeder()->seed();

        $ids = DB::table('role_permissions')->pluck('id')->all();
        $this->assertCount(3, $ids);
        foreach ($ids as $id) {
            $this->assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', (string) $id);
        }
    }

    public function test_a_pivot_with_an_auto_increment_key_is_left_to_the_database(): void
    {
        $this->dropAuthzTables();
        $this->createAuthzTables(pivotKey: 'auto');

        $this->seeder()->seed();

        $this->assertSame([1, 2, 3], array_map('intval', DB::table('role_permissions')->orderBy('id')->pluck('id')->all()));
    }

    private function grantCount(string $roleSlug): int
    {
        $roleId = DB::table('roles')->where('slug', $roleSlug)->value('id');

        return DB::table('role_permissions')->where('role_id', $roleId)->count();
    }
}
