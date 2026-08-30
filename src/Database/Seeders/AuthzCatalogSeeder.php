<?php

declare(strict_types=1);

namespace Dxs\Auth\Database\Seeders;

use Dxs\Auth\Authorization\PermissionCatalog;
use Dxs\Auth\Models\AuthzPermission;
use Dxs\Auth\Models\AuthzRole;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Đưa danh mục `config/authz.php` xuống bảng cục bộ: `permissions`, vai TOÀN HỆ
 * THỐNG trong `roles`, và các cặp nối trong `role_permissions`.
 *
 * ## Guard: `wasRecentlyCreated`, KHÔNG phải `sync()`
 *
 * `role_permissions` là dữ liệu **tổ chức sửa được** ở nhiều consumer (Tempo có
 * hẳn `PUT /hq/{brand}/iam/roles/{role}` cho nó). Một `$role->permissions()->sync($slugs)`
 * chạy mỗi lần deploy sẽ tái áp lựa chọn của package lên lựa chọn của tổ chức —
 * tức âm thầm cấp lại đúng cái quyền họ vừa gỡ, và không để lại một dòng log.
 *
 * Nên seeder chỉ tạo cặp nối khi CHÍNH hàng đó vừa ra đời:
 *
 * - permission `wasRecentlyCreated` — slug mới toanh, tổ chức chưa từng thấy nó,
 *   nên chưa từng có ý kiến gì về nó. Đây là guard mà UPGRADING.md gọi tên.
 * - HOẶC vai `wasRecentlyCreated` — vai mới toanh cũng chưa có lịch sử để cướp.
 *   Thiếu vế này thì một vai mới thêm vào danh mục sẽ ra đời RỖNG khi mọi slug
 *   của nó đã tồn tại từ trước, và không có gì báo.
 *
 * Cả hai vế đều là "hàng này vừa sinh ra". Không vế nào chạm một cặp đã tồn tại,
 * và không vế nào XOÁ bất cứ cặp nào — gỡ quyền vẫn là việc của tổ chức.
 */
final class AuthzCatalogSeeder
{
    /**
     * @return array{permissions_created: int, roles_created: int, grants_created: int}
     */
    public function seed(): array
    {
        $error = PermissionCatalog::validationError(PermissionCatalog::rawCatalog());
        if ($error !== null) {
            throw new RuntimeException($error);
        }

        $this->assertTablesExist();

        $permissionsCreated = 0;
        $rolesCreated = 0;
        $grantsCreated = 0;

        /** @var array<string, AuthzPermission> $permissions */
        $permissions = [];

        foreach (PermissionCatalog::permissions() as $entry) {
            $permission = AuthzPermission::query()->firstOrCreate(
                ['slug' => $entry['slug']],
                array_filter([
                    'name' => $entry['display_name'],
                    'group' => $entry['group'],
                ], static fn (mixed $value): bool => $value !== null),
            );

            $permissions[$entry['slug']] = $permission;
            $permissionsCreated += $permission->wasRecentlyCreated ? 1 : 0;
        }

        foreach (PermissionCatalog::roles() as $entry) {
            $role = AuthzRole::query()->firstOrCreate(
                ['console_organization_id' => null, 'slug' => $entry['role']],
                ['name' => $entry['display_name'], 'level' => $entry['level']],
            );

            $rolesCreated += $role->wasRecentlyCreated ? 1 : 0;

            foreach ($entry['permissions'] as $slug) {
                $permission = $permissions[$slug] ?? null;
                if ($permission === null) {
                    continue;
                }

                // Cặp đã có lịch sử ⇒ tổ chức sở hữu nó, package đứng ngoài.
                if (! $permission->wasRecentlyCreated && ! $role->wasRecentlyCreated) {
                    continue;
                }

                $grantsCreated += $this->grant((string) $role->getKey(), (string) $permission->getKey());
            }
        }

        return [
            'permissions_created' => $permissionsCreated,
            'roles_created' => $rolesCreated,
            'grants_created' => $grantsCreated,
        ];
    }

    /**
     * Slug trong danh mục mà bảng cục bộ CHƯA có. Dùng cho `--dry-run`, và là
     * phép đo duy nhất trả lời được "seed lần này sẽ ghi gì" mà không ghi gì.
     *
     * @return list<string>
     */
    public function pendingSlugs(): array
    {
        $this->assertTablesExist();

        $declared = PermissionCatalog::slugs();
        if ($declared === []) {
            return [];
        }

        $existing = DB::table(PermissionCatalog::table('permissions'))
            ->whereIn('slug', $declared)
            ->pluck('slug')
            ->all();

        return array_values(array_diff($declared, $existing));
    }

    private function assertTablesExist(): void
    {
        foreach (['permissions', 'roles', 'role_permissions'] as $key) {
            $table = PermissionCatalog::table($key);
            if (! Schema::hasTable($table)) {
                throw new RuntimeException("Authz table [{$table}] does not exist — publish the package schemas and migrate first.");
            }
        }
    }

    /** @return int 1 nếu vừa tạo cặp nối, 0 nếu cặp đã có. */
    private function grant(string $roleId, string $permissionId): int
    {
        $table = PermissionCatalog::table('role_permissions');

        $exists = DB::table($table)
            ->where('role_id', $roleId)
            ->where('permission_id', $permissionId)
            ->exists();

        if ($exists) {
            return 0;
        }

        $row = ['role_id' => $roleId, 'permission_id' => $permissionId];
        $columns = Schema::getColumnListing($table);
        $now = Carbon::now();

        if (in_array('created_at', $columns, true)) {
            $row['created_at'] = $now;
        }
        if (in_array('updated_at', $columns, true)) {
            $row['updated_at'] = $now;
        }

        // Bảng nối do consumer sinh: có thể có khoá chính uuid, có thể là
        // auto-increment, có thể không có cột id nào. Chỉ tự đặt id khi cột đó
        // tồn tại VÀ không phải số — nhét uuid vào một cột integer là hỏng.
        if (in_array('id', $columns, true) && ! $this->isIntegerColumn($table, 'id')) {
            $row['id'] = (string) Str::uuid();
        }

        DB::table($table)->insert($row);

        return 1;
    }

    private function isIntegerColumn(string $table, string $column): bool
    {
        $type = strtolower((string) Schema::getColumnType($table, $column));

        return str_contains($type, 'int') || str_contains($type, 'serial');
    }
}
