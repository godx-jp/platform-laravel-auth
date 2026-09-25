<?php

declare(strict_types=1);

namespace Dxs\Auth\Console;

use Dxs\Auth\Support\OrganizationConfigurationGuard;
use Illuminate\Console\Command;

/**
 * `php artisan sso:doctor` — print SSO organization env diagnostics so operators
 * can spot the console-vs-internal UUID mix-up before hitting callback failures.
 */
final class DoctorCommand extends Command
{
    protected $signature = 'sso:doctor';

    protected $description = 'Report SSO organization configuration (console vs internal UUIDs)';

    public function handle(): int
    {
        $this->components->info('SSO organization configuration');

        $findings = OrganizationConfigurationGuard::diagnose();
        $hasProblem = false;

        foreach ($findings as $line) {
            if (str_starts_with($line, 'Problem: ')) {
                $hasProblem = true;
                $this->components->error(substr($line, strlen('Problem: ')));
            } else {
                $this->line('  '.$line);
            }
        }

        if (! OrganizationConfigurationGuard::consumerLooksConfigured()) {
            $this->components->warn('SSO_CLIENT_ID / SSO_CLIENT_SECRET are not both set — finish OAuth client env before testing login.');
        }

        $this->newLine();
        $this->line('  Reference: docs/onboarding.md Step 2 (two organization UUIDs for the same tenant).');

        return $hasProblem ? self::FAILURE : self::SUCCESS;
    }
}
