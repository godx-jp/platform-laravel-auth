<?php

declare(strict_types=1);

namespace Dxs\Auth\Console;

use Dxs\Auth\Authorization\PermissionCatalog;
use Dxs\Auth\Database\Seeders\AuthzCatalogSeeder;
use Illuminate\Console\Command;
use RuntimeException;

/**
 * `php artisan dxs:seed-authz [--dry-run]`
 *
 * Đưa danh mục `config/authz.php` XUỐNG bảng cục bộ. Đối xứng với
 * {@see SyncAuthzCommand}, đẩy đúng danh mục đó LÊN Platform.
 *
 * Vì sao là một LỆNH chứ không chạy lúc boot: seed là ghi vào DB. Chạy nó mỗi
 * lần provider boot là một lượt ghi trên mỗi request — và một lượt ghi không ai
 * nhìn, vào bất cứ giờ nào. Ghi vào DB phải là một hành động có người gọi tên.
 */
final class SeedAuthzCommand extends Command
{
    protected $signature = 'dxs:seed-authz {--dry-run : Print the slugs that would be created without writing}';

    protected $description = 'Seed this service\'s authorization catalog into the local permission tables';

    public function handle(AuthzCatalogSeeder $seeder): int
    {
        $catalog = PermissionCatalog::rawCatalog();

        $count = is_countable($catalog['permissions']) ? count($catalog['permissions']) : 0;
        if ($count === 0) {
            $this->warn('No permissions declared in config/authz.php — nothing to seed.');

            return self::SUCCESS;
        }

        $error = PermissionCatalog::validationError($catalog);
        if ($error !== null) {
            $this->error($error);

            return self::FAILURE;
        }

        try {
            if ($this->option('dry-run')) {
                $pending = $seeder->pendingSlugs();

                $this->line($pending === []
                    ? 'Every declared permission already exists — nothing to create.'
                    : 'Would create '.count($pending).' permission(s): '.implode(', ', $pending));

                return self::SUCCESS;
            }

            $result = $seeder->seed();
        } catch (RuntimeException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->info(sprintf(
            'Authz catalog seeded: %d permission(s), %d role(s), %d grant(s) created.',
            $result['permissions_created'],
            $result['roles_created'],
            $result['grants_created'],
        ));

        // Nói thẳng cái seeder KHÔNG làm, để không ai tưởng im lặng là đã đồng bộ.
        $this->line('Existing rows were left untouched — role grants an organization has edited are never re-applied.');

        return self::SUCCESS;
    }
}
