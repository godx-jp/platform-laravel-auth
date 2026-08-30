<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Sync\AuthzResources;
use Godx\Sync\PlatformSyncServiceProvider;
use Godx\Sync\Registry\ProjectionMode;
use Godx\Sync\Registry\SyncRegistry;
use Orchestra\Testbench\TestCase;

/**
 * Từ vựng authz đi CHUNG đường ống của platform-laravel-sync.
 *
 * Một role binding giống một chi nhánh ở mọi điểm máy móc quan tâm: có id, có
 * phiên bản, có chủ sở hữu. Dựng đường ống riêng cho quyền là nhân đôi sổ nhận,
 * chống trùng, thứ tự, shadow và đối soát — rồi sửa lỗi hai lần, ở hai chỗ, mãi
 * mãi.
 */
final class AuthzResourcesTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [PlatformSyncServiceProvider::class, SsoClientServiceProvider::class];
    }

    public function test_it_registers_the_authz_vocabulary_into_the_shared_pipeline(): void
    {
        $types = $this->app->make(SyncRegistry::class)->types();

        $this->assertContains(AuthzResources::PERMISSION, $types);
        $this->assertContains(AuthzResources::ROLE, $types);
        $this->assertContains(AuthzResources::ROLE_BINDING, $types);
    }

    public function test_role_binding_requires_branch_id_to_be_present_even_when_null(): void
    {
        // null = MỌI chi nhánh (`all_branches_access`), không phải "không chi
        // nhánh nào". Khoá vắng mặt và khoá mang null là hai chuyện khác nhau;
        // gộp lại thì một binding toàn tổ chức thành binding không phạm vi —
        // tước quyền của đúng những người có quyền rộng nhất, im lặng.
        $required = $this->app->make(SyncRegistry::class)
            ->definition(AuthzResources::ROLE_BINDING)
            ->required();

        $this->assertContains('branch_id', $required);
        $this->assertContains('organization_id', $required);
    }

    public function test_it_ships_no_projector_so_it_cannot_overwrite_a_consumer_schema(): void
    {
        $registry = $this->app->make(SyncRegistry::class);

        foreach (AuthzResources::all() as $type) {
            $this->assertNull(
                $registry->definition($type)->projectorClass(),
                "[{$type}] ships a projector; that means guessing a consumer's permission schema and overwriting live rows.",
            );
        }
    }

    public function test_every_authz_type_stays_in_shadow_until_the_consumer_opts_in(): void
    {
        $registry = $this->app->make(SyncRegistry::class);

        foreach (AuthzResources::all() as $type) {
            $this->assertSame(ProjectionMode::Shadow, $registry->definition($type)->projectionMode());
        }
    }

    public function test_the_package_does_not_reinvent_transport_inbox_or_reconciler(): void
    {
        $ours = glob(__DIR__.'/../src/Sync/*.php') ?: [];

        $this->assertCount(1, $ours, 'src/Sync/ grew beyond vocabulary — machinery belongs in platform-laravel-sync.');
        $this->assertSame('AuthzResources.php', basename((string) $ours[0]));
    }
}
