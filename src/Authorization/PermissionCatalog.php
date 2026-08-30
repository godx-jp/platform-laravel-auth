<?php

declare(strict_types=1);

namespace Dxs\Auth\Authorization;

/**
 * Đầu đọc DUY NHẤT của lược đồ permission (`config/authz.php`).
 *
 * Vì sao gom vào một chỗ: cùng một danh mục nay được BA nơi tiêu thụ — lệnh
 * đồng bộ lên IdP, `Gate::define` mà package tự nạp, và seeder ghi xuống DB.
 * Ba nơi tự đọc `config('authz.permissions')` rồi tự đoán hình dạng là ba cách
 * hiểu khác nhau về cùng một file: một chỗ chấp nhận `display_name` thiếu, chỗ
 * kia nổ, chỗ thứ ba âm thầm bỏ qua cả entry. Đó là hình dạng của bug im lặng,
 * không phải của một lược đồ.
 *
 * Lược đồ của MỘT permission: `slug` (bắt buộc) · `display_name` (mô tả cho
 * người, mặc định = slug) · `group` (nhóm, có thể null).
 *
 * Chú ý: {@see self::rawCatalog()} trả về đúng mảng thô trong config, KHÔNG
 * chuẩn hoá. Payload đẩy lên IdP phải là thứ service khai, không phải thứ
 * package suy diễn hộ — thêm khoá vào payload là đổi hợp đồng với Platform.
 */
final class PermissionCatalog
{
    /** Định dạng slug — cùng luật với thứ Platform nhận. */
    public const SLUG_PATTERN = '/^[a-z0-9][a-z0-9._-]*$/';

    /**
     * Danh mục THÔ, đúng như service khai. Dùng cho payload đồng bộ.
     *
     * @return array{permissions: mixed, roles: mixed, default_role: mixed}
     */
    public static function rawCatalog(): array
    {
        return [
            'permissions' => config('authz.permissions') ?? [],
            'roles' => config('authz.roles') ?? [],
            'default_role' => config('authz.default_role'),
        ];
    }

    /**
     * Permission đã chuẩn hoá, bỏ qua entry không có slug dùng được.
     *
     * @return list<array{slug: string, display_name: string, group: ?string}>
     */
    public static function permissions(): array
    {
        $normalized = [];

        foreach ((array) (config('authz.permissions') ?? []) as $entry) {
            if (! is_array($entry)) {
                continue;
            }

            $slug = $entry['slug'] ?? null;
            if (! is_string($slug) || trim($slug) === '') {
                continue;
            }

            $displayName = $entry['display_name'] ?? null;
            $group = $entry['group'] ?? null;

            $normalized[] = [
                'slug' => $slug,
                'display_name' => is_string($displayName) && trim($displayName) !== '' ? $displayName : $slug,
                'group' => is_string($group) && trim($group) !== '' ? $group : null,
            ];
        }

        return $normalized;
    }

    /** @return list<string> */
    public static function slugs(): array
    {
        return array_values(array_map(
            static fn (array $permission): string => $permission['slug'],
            self::permissions(),
        ));
    }

    /**
     * Vai trò đã chuẩn hoá. `permissions` chỉ giữ slug có thật trong danh mục —
     * một vai trỏ tới slug không khai là lỗi cấu hình, và {@see self::validationError()}
     * bắt nó trước; ở đây ta không im lặng dựng ra quyền không tồn tại.
     *
     * @return list<array{role: string, display_name: string, level: int, permissions: list<string>}>
     */
    public static function roles(): array
    {
        $known = array_flip(self::slugs());
        $normalized = [];

        foreach ((array) (config('authz.roles') ?? []) as $entry) {
            if (! is_array($entry)) {
                continue;
            }

            $role = $entry['role'] ?? null;
            if (! is_string($role) || trim($role) === '') {
                continue;
            }

            $displayName = $entry['display_name'] ?? null;
            $level = $entry['level'] ?? 0;

            $permissions = [];
            foreach ((array) ($entry['permissions'] ?? []) as $slug) {
                if (is_string($slug) && isset($known[$slug])) {
                    $permissions[] = $slug;
                }
            }

            $normalized[] = [
                'role' => $role,
                'display_name' => is_string($displayName) && trim($displayName) !== '' ? $displayName : $role,
                'level' => is_int($level) ? $level : (int) $level,
                'permissions' => array_values(array_unique($permissions)),
            ];
        }

        return $normalized;
    }

    public static function defaultRole(): ?string
    {
        $default = config('authz.default_role');

        return is_string($default) && trim($default) !== '' ? $default : null;
    }

    /**
     * Kiểm lược đồ. Trả về null khi hợp lệ, ngược lại là câu lỗi ĐẦU TIÊN.
     *
     * Trả về câu chứ không ném: cả lệnh đồng bộ lẫn lệnh seed đều phải dừng
     * TRƯỚC khi chạm mạng hoặc chạm DB, và cả hai muốn tự in lỗi theo kiểu của
     * lệnh.
     *
     * @param  array<string, mixed>  $catalog
     */
    public static function validationError(array $catalog): ?string
    {
        $permissions = $catalog['permissions'] ?? null;
        if (! is_array($permissions)) {
            return 'Permission catalog must contain a permissions array.';
        }

        $slugs = [];
        foreach ($permissions as $index => $permission) {
            $slug = is_array($permission) ? ($permission['slug'] ?? null) : null;
            if (! is_string($slug) || trim($slug) === '') {
                return "Permission at index {$index} must have a non-empty string slug.";
            }

            if (preg_match(self::SLUG_PATTERN, $slug) !== 1) {
                return "Permission slug [{$slug}] has an invalid format.";
            }

            if (isset($slugs[$slug])) {
                return "Permission slug [{$slug}] is duplicated.";
            }

            $displayName = $permission['display_name'] ?? null;
            if ($displayName !== null && (! is_string($displayName) || trim($displayName) === '')) {
                return "Permission slug [{$slug}] has a non-string display_name.";
            }

            $group = $permission['group'] ?? null;
            if ($group !== null && (! is_string($group) || trim($group) === '')) {
                return "Permission slug [{$slug}] has a non-string group.";
            }

            $slugs[$slug] = true;
        }

        $roles = $catalog['roles'] ?? [];
        if (! is_array($roles)) {
            return 'Permission catalog roles must be an array.';
        }

        $roleNames = [];
        foreach ($roles as $index => $role) {
            $roleName = is_array($role) ? ($role['role'] ?? null) : null;
            $rolePermissions = is_array($role) ? ($role['permissions'] ?? null) : null;
            if (! is_string($roleName) || trim($roleName) === '' || ! is_array($rolePermissions)) {
                return "Role at index {$index} must contain a role name and permissions array.";
            }

            if (isset($roleNames[$roleName])) {
                return "Role [{$roleName}] is duplicated.";
            }
            $roleNames[$roleName] = true;

            foreach ($rolePermissions as $permissionSlug) {
                if (! is_string($permissionSlug) || ! isset($slugs[$permissionSlug])) {
                    return "Role at index {$index} references an unknown permission.";
                }
            }
        }

        $defaultRole = $catalog['default_role'] ?? null;
        if ($defaultRole !== null && (! is_string($defaultRole) || ! isset($roleNames[$defaultRole]))) {
            return 'Default role must reference a declared role.';
        }

        return null;
    }

    /** Tên bảng authz — consumer sở hữu schema nên đường dẫn phải cấu hình được. */
    public static function table(string $key): string
    {
        $default = [
            'permissions' => 'permissions',
            'roles' => 'roles',
            'role_permissions' => 'role_permissions',
            'role_user' => 'role_user_pivots',
        ][$key] ?? $key;

        $configured = config("sso.authz.tables.{$key}", $default);

        return is_string($configured) && $configured !== '' ? $configured : $default;
    }
}
