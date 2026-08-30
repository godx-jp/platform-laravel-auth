<?php

declare(strict_types=1);

namespace Dxs\Auth\Models;

use Dxs\Auth\Authorization\PermissionCatalog;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * Model NỘI BỘ của package, trỏ vào bảng `permissions` của consumer.
 *
 * Vì sao package tự mang model thay vì dùng model sinh bởi Omnify ở consumer:
 * class đó không tồn tại ở đây (schema được publish rồi sinh mã BÊN consumer),
 * nên package không có tên class nào để gọi. Nhưng seeder cần đúng một thứ mà
 * query builder không có: `wasRecentlyCreated` — cái guard mà UPGRADING.md gọi
 * tên. Một model mỏng là cách rẻ nhất để có nó thật, thay vì tự mô phỏng.
 *
 * KHÔNG đăng ký vào container, KHÔNG dùng ngoài seeder.
 */
final class AuthzPermission extends Model
{
    public $incrementing = false;

    public $timestamps = true;

    protected $keyType = 'string';

    protected $guarded = [];

    public function getTable(): string
    {
        return PermissionCatalog::table('permissions');
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
