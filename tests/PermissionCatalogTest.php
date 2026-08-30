<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Authorization\PermissionCatalog;
use Dxs\Auth\SsoClientServiceProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Lược đồ permission: `config/authz.php` khai slug + mô tả + nhóm, và
 * {@see PermissionCatalog} là đầu đọc DUY NHẤT của nó.
 *
 * Luật đắt nhất ở đây: {@see self::test_the_sync_payload_is_the_raw_declaration()}.
 * Chuẩn hoá là chuyện NỘI BỘ (Gate + seeder cần hình dạng đầy đủ); payload đẩy
 * lên Platform phải là đúng thứ service khai, vì nó là một hợp đồng.
 */
final class PermissionCatalogTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    public function test_display_name_defaults_to_the_slug_and_group_may_be_absent(): void
    {
        config()->set('authz.permissions', [
            ['slug' => 'dashboard.view'],
            ['slug' => 'employees.view', 'display_name' => 'Employees · View', 'group' => 'employees'],
        ]);

        $this->assertSame([
            ['slug' => 'dashboard.view', 'display_name' => 'dashboard.view', 'group' => null],
            ['slug' => 'employees.view', 'display_name' => 'Employees · View', 'group' => 'employees'],
        ], PermissionCatalog::permissions());
    }

    public function test_entries_without_a_usable_slug_are_dropped_not_guessed(): void
    {
        config()->set('authz.permissions', [
            'not-an-array',
            ['display_name' => 'No slug'],
            ['slug' => '  '],
            ['slug' => 'dashboard.view'],
        ]);

        $this->assertSame(['dashboard.view'], PermissionCatalog::slugs());
    }

    public function test_a_role_never_carries_a_slug_the_catalog_does_not_declare(): void
    {
        config()->set('authz.permissions', [['slug' => 'dashboard.view']]);
        config()->set('authz.roles', [
            ['role' => 'staff', 'permissions' => ['dashboard.view', 'ghost.view', 'dashboard.view']],
        ]);

        $this->assertSame([
            ['role' => 'staff', 'display_name' => 'staff', 'level' => 0, 'permissions' => ['dashboard.view']],
        ], PermissionCatalog::roles());
    }

    public function test_the_sync_payload_is_the_raw_declaration(): void
    {
        $declared = [
            'permissions' => [['slug' => 'dashboard.view']],
            'roles' => [['role' => 'staff', 'permissions' => ['dashboard.view']]],
            'default_role' => 'staff',
        ];
        config()->set('authz', $declared);

        $this->assertSame($declared, PermissionCatalog::rawCatalog());
    }

    /**
     * @param  array<string, mixed>  $catalog
     */
    #[DataProvider('invalidCatalogs')]
    public function test_the_schema_is_validated(array $catalog, string $expected): void
    {
        $this->assertStringContainsString($expected, (string) PermissionCatalog::validationError($catalog));
    }

    /** @return array<string, array{0: array<string, mixed>, 1: string}> */
    public static function invalidCatalogs(): array
    {
        return [
            'permissions not an array' => [['permissions' => 'nope'], 'must contain a permissions array'],
            'missing slug' => [['permissions' => [['display_name' => 'x']]], 'non-empty string slug'],
            'bad slug format' => [['permissions' => [['slug' => 'Invalid Slug']]], 'invalid format'],
            'duplicate slug' => [['permissions' => [['slug' => 'a'], ['slug' => 'a']]], 'duplicated'],
            'non-string display_name' => [['permissions' => [['slug' => 'a', 'display_name' => 42]]], 'non-string display_name'],
            'non-string group' => [['permissions' => [['slug' => 'a', 'group' => []]]], 'non-string group'],
            'roles not an array' => [['permissions' => [['slug' => 'a']], 'roles' => 'nope'], 'roles must be an array'],
            'role without permissions' => [['permissions' => [['slug' => 'a']], 'roles' => [['role' => 'r']]], 'role name and permissions array'],
            'duplicate role' => [['permissions' => [['slug' => 'a']], 'roles' => [['role' => 'r', 'permissions' => []], ['role' => 'r', 'permissions' => []]]], 'is duplicated'],
            'unknown permission in role' => [['permissions' => [['slug' => 'a']], 'roles' => [['role' => 'r', 'permissions' => ['b']]]], 'unknown permission'],
            'unknown default role' => [['permissions' => [['slug' => 'a']], 'roles' => [], 'default_role' => 'nope'], 'Default role must reference'],
        ];
    }

    public function test_a_valid_catalog_has_no_error(): void
    {
        $this->assertNull(PermissionCatalog::validationError([
            'permissions' => [['slug' => 'dashboard.view', 'display_name' => 'Dashboard · View', 'group' => 'dashboard']],
            'roles' => [['role' => 'staff', 'permissions' => ['dashboard.view']]],
            'default_role' => 'staff',
        ]));
    }

    public function test_table_names_are_configurable_with_documented_defaults(): void
    {
        $this->assertSame('permissions', PermissionCatalog::table('permissions'));
        $this->assertSame('role_user_pivots', PermissionCatalog::table('role_user'));

        config()->set('sso.authz.tables.role_user', 'tenant_role_user');
        $this->assertSame('tenant_role_user', PermissionCatalog::table('role_user'));

        config()->set('sso.authz.tables.role_user', '');
        $this->assertSame('role_user_pivots', PermissionCatalog::table('role_user'));
    }
}
