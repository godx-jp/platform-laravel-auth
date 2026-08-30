<?php

declare(strict_types=1);

namespace Dxs\Auth\Models;

use Dxs\Auth\Authorization\PermissionCatalog;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * Model NỘI BỘ của package trỏ vào bảng `roles`. Xem ghi chú ở
 * {@see AuthzPermission} về lý do package tự mang model.
 *
 * Seeder chỉ chạm vai TOÀN HỆ THỐNG (`console_organization_id` null) — vai
 * riêng của một tổ chức là dữ liệu tổ chức đó sở hữu, package không có việc gì
 * ở đó.
 */
final class AuthzRole extends Model
{
    public $incrementing = false;

    public $timestamps = true;

    protected $keyType = 'string';

    protected $guarded = [];

    public function getTable(): string
    {
        return PermissionCatalog::table('roles');
    }

    protected static function booted(): void
    {
        self::creating(function (self $model): void {
            if ($model->getKey() === null || $model->getKey() === '') {
                $model->setAttribute($model->getKeyName(), (string) Str::uuid());
            }
        });
    }
}
