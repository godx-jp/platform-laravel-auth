<?php

declare(strict_types=1);

namespace Dxs\Auth\Authorization;

use Dxs\Auth\Sync\AuthzResources;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Throwable;

/**
 * Trả lời một ability của danh mục TỪ BẢNG CỤC BỘ (permissions ↔ role_permissions
 * ↔ role_user_pivots) — tức từ đúng thứ mà seeder của package ghi xuống.
 *
 * Đây là vế thứ hai của thay đổi 1.0.0: `Gate::before` nay trả `null` khi không
 * phân giải được trên Platform, và câu trả lời rơi xuống ĐÂY thay vì rơi vào
 * hư không. Nếu không có lớp này thì "trả null" chỉ đổi một deny im lặng thành
 * một deny im lặng khác.
 *
 * Ba luật của lớp này:
 *
 * - **Nó KHÔNG phải nguồn sự thật.** Platform là. Lớp này chỉ được hỏi khi
 *   Platform không trả lời được (không token / không org).
 * - **Thiếu bảng KHÔNG phải lỗi.** Consumer có thể chưa publish schema authz,
 *   hoặc cố tình không dùng bảng nào cả. Khi đó câu trả lời là "không cấp",
 *   không phải một exception ném giữa một lượt kiểm quyền.
 * - **`organization_id IS NULL` nghĩa là MỌI tổ chức**, không phải "không tổ
 *   chức nào" — cùng ruling với `branch_id` ở {@see AuthzResources}.
 *   Gộp hai nghĩa đó lại là tước quyền của đúng những người có quyền rộng nhất.
 */
final class LocalAbilityResolver
{
    /** @var array<string, bool> */
    private array $tableExists = [];

    /** @var array<string, bool> */
    private array $columnExists = [];

    public function allows(Authenticatable $user, string $slug): bool
    {
        try {
            return $this->query($user, $slug);
        } catch (Throwable $exception) {
            // Một lượt kiểm quyền không được phép làm đổ cả trang. Fail CLOSED,
            // cùng lối với PermissionClient::resolveFor().
            Log::warning('SSO local ability lookup failed — denying (fail-closed): '.$exception->getMessage());

            return false;
        }
    }

    private function query(Authenticatable $user, string $slug): bool
    {
        $identifier = $user->getAuthIdentifier();
        if (! is_string($identifier) && ! is_int($identifier)) {
            return false;
        }
        if ((string) $identifier === '') {
            return false;
        }

        $permissions = PermissionCatalog::table('permissions');
        $rolePermissions = PermissionCatalog::table('role_permissions');
        $roleUser = PermissionCatalog::table('role_user');
        $roles = PermissionCatalog::table('roles');

        foreach ([$permissions, $rolePermissions, $roleUser] as $table) {
            if (! $this->hasTable($table)) {
                return false;
            }
        }

        $query = DB::table($permissions.' as p')
            ->join($rolePermissions.' as rp', 'rp.permission_id', '=', 'p.id')
            ->join($roleUser.' as ru', 'ru.role_id', '=', 'rp.role_id')
            ->where('p.slug', $slug)
            ->where('ru.user_id', $identifier);

        // Vai đã xoá mềm không còn cấp quyền.
        if ($this->hasTable($roles) && $this->hasColumn($roles, 'deleted_at')) {
            $query->join($roles.' as r', 'r.id', '=', 'rp.role_id')->whereNull('r.deleted_at');
        }

        $organization = $this->stringAttribute($user, 'console_organization_id');
        if ($organization !== null && $this->hasColumn($roleUser, 'organization_id')) {
            $query->where(fn ($scope) => $scope
                ->whereNull('ru.organization_id')
                ->orWhere('ru.organization_id', $organization));
        }

        return $query->exists();
    }

    private function stringAttribute(Authenticatable $user, string $key): ?string
    {
        $value = data_get($user, $key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function hasTable(string $table): bool
    {
        return $this->tableExists[$table] ??= Schema::hasTable($table);
    }

    private function hasColumn(string $table, string $column): bool
    {
        return $this->columnExists[$table.'.'.$column] ??= Schema::hasColumn($table, $column);
    }
}
