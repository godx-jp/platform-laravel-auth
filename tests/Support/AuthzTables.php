<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests\Support;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Dựng đúng những bảng authz mà consumer sinh ra từ schema Omnify của package
 * (`schemas/Permission.yaml`, `Role.yaml`, `RolePermission.yaml`,
 * `RoleUserPivot.yaml`), để test đo trên hình dạng thật chứ không trên một
 * hình dạng thuận tay.
 */
trait AuthzTables
{
    /** @param 'none'|'uuid'|'auto' $pivotKey hình dạng khoá chính của bảng nối */
    protected function createAuthzTables(string $pivotKey = 'none'): void
    {
        Schema::create('permissions', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('name', 100)->unique();
            $table->string('slug', 100)->unique();
            $table->string('group', 50)->nullable();
            $table->timestamps();
        });

        Schema::create('roles', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('console_organization_id', 36)->nullable();
            $table->string('name', 100);
            $table->string('slug', 100);
            $table->text('description')->nullable();
            $table->integer('level')->default(0);
            $table->timestamps();
            $table->softDeletes();
        });

        Schema::create('role_permissions', function (Blueprint $table) use ($pivotKey): void {
            match ($pivotKey) {
                'uuid' => $table->uuid('id')->primary(),
                'auto' => $table->id(),
                default => null,
            };
            $table->uuid('role_id');
            $table->uuid('permission_id');
            $table->timestamps();
        });

        Schema::create('role_user_pivots', function (Blueprint $table): void {
            $table->id();
            $table->uuid('role_id');
            $table->string('user_id', 36);
            $table->uuid('organization_id')->nullable();
            $table->uuid('branch_id')->nullable();
            $table->timestamps();
        });
    }

    protected function dropAuthzTables(): void
    {
        foreach (['role_permissions', 'role_user_pivots', 'roles', 'permissions'] as $table) {
            Schema::dropIfExists($table);
        }
    }
}
