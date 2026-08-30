<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\AuthzTables;
use Illuminate\Auth\GenericUser;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase;

/**
 * Thay đổi phá vỡ số 2 của 1.0.0: package TỰ `Gate::define` cho mọi slug trong
 * danh mục, và định nghĩa đó đọc bảng cục bộ — đúng thứ `dxs:seed-authz` ghi.
 *
 * Đây là vế bắt buộc đi kèm thay đổi số 1: nếu không có định nghĩa nào, "trả
 * null" chỉ đổi một deny im lặng thành một deny im lặng khác.
 */
final class CatalogAbilityDefinitionTest extends TestCase
{
    use AuthzTables;

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('database.default', 'testing');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('authz.permissions', [
            ['slug' => 'dashboard.view', 'display_name' => 'Dashboard · View', 'group' => 'dashboard'],
            ['slug' => 'employees.delete', 'display_name' => 'Employees · Delete', 'group' => 'employees'],
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createAuthzTables();
        Http::fake();
    }

    protected function tearDown(): void
    {
        $this->dropAuthzTables();

        parent::tearDown();
    }

    public function test_the_package_defines_a_gate_ability_for_every_declared_slug(): void
    {
        $this->assertTrue(Gate::has('dashboard.view'));
        $this->assertTrue(Gate::has('employees.delete'));
        $this->assertFalse(Gate::has('not.declared'));
    }

    public function test_a_grant_in_the_local_tables_answers_when_the_platform_cannot(): void
    {
        $this->grant('u-1', 'dashboard.view');

        $user = new GenericUser(['id' => 'u-1']);

        $this->assertTrue(Gate::forUser($user)->allows('dashboard.view'));
        $this->assertFalse(Gate::forUser($user)->allows('employees.delete'));
        Http::assertNothingSent();
    }

    public function test_another_users_grant_is_not_borrowed(): void
    {
        $this->grant('u-1', 'dashboard.view');

        $this->assertFalse(Gate::forUser(new GenericUser(['id' => 'u-2']))->allows('dashboard.view'));
    }

    public function test_a_grant_scoped_to_another_organization_does_not_answer(): void
    {
        $this->grant('u-1', 'dashboard.view', organization: 'org-other');

        $user = new GenericUser(['id' => 'u-1', 'console_organization_id' => 'org-1']);

        $this->assertFalse(Gate::forUser($user)->allows('dashboard.view'));
    }

    public function test_a_grant_scoped_to_this_organization_answers(): void
    {
        $this->grant('u-1', 'dashboard.view', organization: 'org-1');

        $user = new GenericUser(['id' => 'u-1', 'console_organization_id' => 'org-1']);

        $this->assertTrue(Gate::forUser($user)->allows('dashboard.view'));
    }

    public function test_a_null_scoped_grant_means_every_organization_not_none(): void
    {
        $this->grant('u-1', 'dashboard.view', organization: null);

        $user = new GenericUser(['id' => 'u-1', 'console_organization_id' => 'org-1']);

        $this->assertTrue(Gate::forUser($user)->allows('dashboard.view'));
    }

    public function test_a_soft_deleted_role_stops_granting(): void
    {
        $roleId = $this->grant('u-1', 'dashboard.view');
        DB::table('roles')->where('id', $roleId)->update(['deleted_at' => now()]);

        $this->assertFalse(Gate::forUser(new GenericUser(['id' => 'u-1']))->allows('dashboard.view'));
    }

    public function test_a_consumer_definition_overrides_the_package_one(): void
    {
        // Provider của app boot SAU package, nên define sau đè define trước.
        Gate::define('dashboard.view', fn (): bool => true);

        $this->assertTrue(Gate::forUser(new GenericUser(['id' => 'nobody']))->allows('dashboard.view'));
    }

    public function test_missing_authz_tables_deny_instead_of_throwing(): void
    {
        $this->dropAuthzTables();

        $this->assertFalse(Gate::forUser(new GenericUser(['id' => 'u-1']))->allows('dashboard.view'));
    }

    public function test_a_malformed_authz_schema_denies_instead_of_throwing(): void
    {
        // Bảng CÓ mặt nhưng thiếu cột — rào `Schema::hasTable` không bắt được
        // trường hợp này, nên đây là phép đo riêng cho lớp fail-closed. Một
        // lượt kiểm quyền không được phép làm đổ cả trang.
        Schema::drop('role_permissions');
        Schema::create('role_permissions', function (Blueprint $table): void {
            $table->uuid('role_id');
        });

        $this->assertFalse(Gate::forUser(new GenericUser(['id' => 'u-1']))->allows('dashboard.view'));
    }

    /** @return string id của vai vừa dùng để cấp */
    private function grant(string $userId, string $slug, ?string $organization = null): string
    {
        $permissionId = (string) Str::uuid();
        $roleId = (string) Str::uuid();

        DB::table('permissions')->insert([
            'id' => $permissionId, 'name' => $slug, 'slug' => $slug, 'group' => null,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('roles')->insert([
            'id' => $roleId, 'console_organization_id' => null, 'name' => 'Role '.$slug,
            'slug' => 'role-'.$slug, 'level' => 0, 'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('role_permissions')->insert([
            'role_id' => $roleId, 'permission_id' => $permissionId,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('role_user_pivots')->insert([
            'role_id' => $roleId, 'user_id' => $userId, 'organization_id' => $organization,
            'branch_id' => null, 'created_at' => now(), 'updated_at' => now(),
        ]);

        return $roleId;
    }
}
