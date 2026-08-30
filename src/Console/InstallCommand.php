<?php

declare(strict_types=1);

namespace Dxs\Auth\Console;

use Illuminate\Console\Command;

/**
 * `php artisan sso:install` — one-shot downstream setup: publishes the sso
 * config, the users-table identity migration and the starter authz catalog
 * (plus, with --provisioner, an app-owned UserProvisioner stub for custom
 * mappings), then prints exactly what is left to do by hand.
 */
final class InstallCommand extends Command
{
    protected $signature = 'sso:install
        {--provisioner : Also publish an app-owned App\Sso\UserProvisioner stub}
        {--force : Overwrite previously published files}';

    protected $description = 'Publish everything a downstream service needs for platform SSO';

    public function handle(): int
    {
        $force = (bool) $this->option('force');

        $this->publishTag('sso-config', $force);
        $this->publishTag('sso-migrations', $force);
        $this->publishTag('sso-authz', $force);

        if ($this->option('provisioner')) {
            $this->publishTag('sso-provisioner', $force);
            $this->components->warn('Bind your provisioner: $this->app->singleton(ProvisionsUsers::class, App\Sso\UserProvisioner::class);');
        } else {
            $this->components->info('Using the package DatabaseUserProvisioner (auth.providers.users.model) — publish a custom one later with `sso:install --provisioner`.');
        }

        $this->components->info('Next steps:');
        $this->line('  1. Set the SSO_* env values (issuer, service slug, client id/secret, redirect URI, organization ids).');
        $this->line('  2. php artisan migrate');
        $this->line('  3. Point unauthenticated users at /auth/redirect (a named `login` redirect is registered for you unless your app already defines one).');
        $this->line('  4. Declare your catalog in config/authz.php and run `php artisan dxs:sync-authz --dry-run`.');
        $this->line('  5. php artisan dxs:seed-authz  (writes the same catalog into the local permission tables)');
        $this->line('  See docs/onboarding.md in the package for the full walkthrough.');

        return self::SUCCESS;
    }

    private function publishTag(string $tag, bool $force): void
    {
        $this->call('vendor:publish', array_filter([
            '--tag' => $tag,
            '--force' => $force,
        ]));
    }
}
