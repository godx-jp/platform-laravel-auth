<?php

declare(strict_types=1);

namespace Dxs\Auth\Sync;

use Godx\Sync\Registry\SyncRegistry;

/**
 * Từ vựng tài nguyên AUTHZ, khai vào đường ống chung của
 * `godx-jp/platform-laravel-sync`.
 *
 * Vì sao ở đây chứ không ở package sync: package nào DIỄN GIẢI một tài nguyên
 * thì package đó sở hữu định nghĩa của nó. Sync biết cách vận chuyển, chống
 * trùng và đối soát một thứ có id + phiên bản + chủ sở hữu; nó không biết —
 * và không nên biết — rằng một `role_binding` quyết định ai được bấm nút nào.
 *
 * Vì sao KHÔNG dựng một đường ống riêng cho quyền: một role binding giống một
 * chi nhánh ở mọi điểm mà máy móc quan tâm. Dựng đường ống thứ hai là nhân đôi
 * sổ nhận, chống trùng, thứ tự, shadow và đối soát — rồi phải sửa lỗi hai lần,
 * ở hai chỗ, mãi mãi. Cái tên `authz-sync` là cái bẫy đó dưới dạng một cái tên.
 */
final class AuthzResources
{
    public const PERMISSION = 'godx.authz.permission';

    public const ROLE = 'godx.authz.role';

    public const ROLE_BINDING = 'godx.authz.role_binding';

    /** @var array<string, list<string>> */
    private const REQUIRED = [
        self::PERMISSION => ['id', 'slug'],
        self::ROLE => ['id', 'slug', 'permissions'],

        // `branch_id` PHẢI có mặt, kể cả khi mang null.
        //
        // null nghĩa là MỌI chi nhánh (`all_branches_access`), không phải
        // "không chi nhánh nào". Khoá vắng mặt và khoá mang null vì thế là hai
        // chuyện khác nhau, và gộp chúng lại biến một binding toàn tổ chức
        // thành một binding không phạm vi — tức tước quyền của đúng những người
        // có quyền rộng nhất, im lặng.
        self::ROLE_BINDING => ['id', 'user_id', 'role_id', 'organization_id', 'branch_id'],
    ];

    /** @return list<string> */
    public static function all(): array
    {
        return array_keys(self::REQUIRED);
    }

    /**
     * Khai từ vựng vào registry.
     *
     * Chỉ khai TỪ VỰNG — không projector. Consumer cất quyền theo lược đồ của
     * riêng nó (Tempo dùng `role_user_pivots`), và một projector "dùng chung"
     * là đoán lược đồ của người khác rồi ghi đè bảng phân quyền đang chạy.
     */
    public static function register(SyncRegistry $registry): void
    {
        foreach (self::REQUIRED as $type => $required) {
            $registry->resource($type)->requires($required);
        }
    }
}
