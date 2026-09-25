<?php

declare(strict_types=1);

namespace Dxs\Auth\Console;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Support\SsoCache;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

/**
 * Pushes this service's authorization catalog UP to the GoDX ID platform, so the
 * platform can build roles from the codes and resolve them for users at login.
 *
 *   php artisan dxs:sync-authz [--dry-run]
 *
 * The catalog is owned by the service in `config/authz.php`
 * (`permissions`, `roles`, `default_role`).
 *
 * Sync mode (`SSO_AUTHZ_MODE`, or auto when `SSO_ADMIN_KEY` is set):
 * - `dev` — local dev-admin mirror: `PUT api/dev/services/{slug}/authz` with `X-Admin-Key`
 * - `admin` — platform admin catalog route (Bearer `SSO_ADMIN_TOKEN`; today often BFF-session only)
 */
final class SyncAuthzCommand extends Command
{
    private const ADMIN_DEFAULT_PATH = 'api/admin/catalog/{service}/authz';

    private const DEV_DEFAULT_PATH = 'api/dev/services/{service}/authz';

    protected $signature = 'dxs:sync-authz {--dry-run : Print the payload without sending} {--if-changed : Skip when the catalog matches the last successful sync}';

    protected $description = 'Sync this service\'s authorization catalog to the GoDX ID platform';

    public function handle(): int
    {
        /** @var array<string, mixed> $catalog */
        $catalog = [
            'permissions' => config('authz.permissions') ?? [],
            'roles' => config('authz.roles') ?? [],
            'default_role' => config('authz.default_role'),
        ];

        $count = is_countable($catalog['permissions']) ? count($catalog['permissions']) : 0;

        if ($count === 0) {
            $this->warn('No permissions declared in config/authz.php — nothing to sync.');

            return self::SUCCESS;
        }

        $validationError = $this->validationError($catalog);
        if ($validationError !== null) {
            $this->error($validationError);

            return self::FAILURE;
        }

        $service = (string) config('sso.service_id');
        if ($service === '') {
            $this->error('SSO_SERVICE_ID is not set — it identifies this service on the platform.');

            return self::FAILURE;
        }

        $mode = $this->resolveAuthzMode();
        if (! in_array($mode, ['admin', 'dev'], true)) {
            $this->error('SSO_AUTHZ_MODE must be `admin` or `dev`.');

            return self::FAILURE;
        }

        $this->line("Syncing {$count} permission code(s) for service [{$service}] ({$mode} mode)");

        $url = $this->authzUrl($service, $mode);

        if ($this->option('dry-run')) {
            $this->line(json_encode($catalog, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

            if ($mode === 'dev') {
                $this->newLine();
                $this->comment('Dev-admin equivalent (runs automatically when SSO_AUTHZ_MODE=dev):');
                $this->line($this->devCurlCommand($url, $catalog));
            }

            return self::SUCCESS;
        }

        $catalogHash = hash('sha256', json_encode([$service, config('sso.issuer'), $mode, $catalog], JSON_THROW_ON_ERROR));
        $hashKey = SsoCache::key('authz-sync:'.$service.':'.$mode);
        if ($this->option('if-changed') && SsoCache::store()->get($hashKey) === $catalogHash) {
            $this->info('Catalog unchanged since the last successful sync — skipping.');

            return self::SUCCESS;
        }

        if ($mode === 'dev') {
            $key = (string) config('sso.admin_key');
            if ($key === '') {
                $this->error('SSO_ADMIN_KEY is not set — required for dev authz sync (X-Admin-Key).');

                return self::FAILURE;
            }

            $response = Http::withHeaders(['X-Admin-Key' => $key])
                ->timeout((int) config('sso.http_timeout', 5))
                ->acceptJson()
                ->put($url, $catalog);
        } else {
            $token = (string) config('sso.admin_token');
            if ($token === '') {
                $this->error('SSO_ADMIN_TOKEN is not set — required for admin authz sync (Bearer).');

                return self::FAILURE;
            }

            $response = Http::withToken($token)
                ->timeout((int) config('sso.http_timeout', 5))
                ->acceptJson()
                ->put($url, $catalog);
        }

        if ($response->failed()) {
            $this->error("Sync failed ({$response->status()}).");

            throw new SsoException('Permission catalog sync failed.');
        }

        SsoCache::store()->forever($hashKey, $catalogHash);
        $this->info("Permission catalog synced ({$count} codes).");

        return self::SUCCESS;
    }

    private function resolveAuthzMode(): string
    {
        $configured = config('sso.authz_mode');
        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        return (string) config('sso.admin_key') !== '' ? 'dev' : 'admin';
    }

    private function authzUrl(string $service, string $mode): string
    {
        $configuredPath = (string) config('sso.authz_path');
        $pathTemplate = $configuredPath;
        if ($mode === 'dev' && $configuredPath === self::ADMIN_DEFAULT_PATH) {
            $pathTemplate = self::DEV_DEFAULT_PATH;
        }

        // The dev-admin mirror routes by SLUG (`services/{slug}/authz`), the admin catalog
        // by `SSO_SERVICE_ID` — so dev mode prefers `SSO_SERVICE_SLUG` when it is set.
        $segment = $service;
        if ($mode === 'dev' && (string) config('sso.service_slug') !== '') {
            $segment = (string) config('sso.service_slug');
        }

        $path = str_replace('{service}', rawurlencode($segment), $pathTemplate);

        return rtrim((string) config('sso.issuer'), '/').'/'.ltrim($path, '/');
    }

    /** @param array<string, mixed> $catalog */
    private function devCurlCommand(string $url, array $catalog): string
    {
        $payload = json_encode($catalog, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        // NEVER the real key: dry-run output lands in CI logs and terminals.
        $keyDisplay = '$SSO_ADMIN_KEY';

        return sprintf(
            'curl -sS -X PUT %s -H %s -H %s --data %s',
            escapeshellarg($url),
            escapeshellarg('X-Admin-Key: '.$keyDisplay),
            escapeshellarg('Content-Type: application/json'),
            escapeshellarg($payload !== false ? $payload : '{}'),
        );
    }

    /** @param array<string, mixed> $catalog */
    private function validationError(array $catalog): ?string
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

            if (preg_match('/^[a-z0-9][a-z0-9._-]*$/', $slug) !== 1) {
                return "Permission slug [{$slug}] has an invalid format.";
            }

            if (isset($slugs[$slug])) {
                return "Permission slug [{$slug}] is duplicated.";
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
}
