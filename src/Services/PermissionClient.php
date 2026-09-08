<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Support\SsoCache;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Consumes the platform's authoritative permission read model. Authorization
 * DECISIONS stay on the platform (EffectiveAccessResolver); the downstream only
 * fetches the resolved permission list for the signed-in user + organization
 * and checks membership locally.
 *
 * NOTE (platform requirement): the endpoint must accept the downstream's OAuth
 * bearer. `/api/sso/me/permissions` is currently `core.auth` (Sanctum session)
 * only — the platform must also allow `idp.verify` (bearer) for downstreams,
 * or expose `/api/sso/service/me/permissions`. Configure via `sso.permissions_path`.
 */
final class PermissionClient
{
    public function __construct(private readonly OidcDiscovery $discovery) {}

    /**
     * @return array{permissions: list<string>, roles: list<mixed>, service_access: array<string, mixed>, contract_version: ?string, evaluated_at: ?string, authoritative: bool}
     */
    public function fetch(string $accessToken, string $organizationId, ?string $branchId = null): array
    {
        $tokenHash = hash('sha256', $accessToken);
        $key = SsoCache::key('perms:'.$tokenHash.':'.sha1($organizationId.'|'.((string) $branchId)));
        $this->indexKey($tokenHash, $key);

        return SsoCache::store()->remember(
            $key,
            (int) config('sso.permissions_ttl', 300),
            fn (): array => $this->fetchFresh($accessToken, $organizationId, $branchId),
        );
    }

    /**
     * Query the authority for this call without reading or writing a positive
     * cache. Use at admission and immediately before each business effect.
     * An unavailable authority throws; never substitute an earlier decision.
     *
     * @return array{permissions: list<string>, roles: list<mixed>, service_access: array<string, mixed>, contract_version: ?string, evaluated_at: ?string, authoritative: bool}
     */
    public function fetchFresh(string $accessToken, string $organizationId, ?string $branchId = null): array
    {
        $url = rtrim((string) config('sso.issuer'), '/').'/'.ltrim((string) config('sso.permissions_path', 'api/sso/me/permissions'), '/');

        try {
            $response = Http::withToken($accessToken)
                ->withoutRedirecting()
                ->timeout((int) config('sso.http_timeout'))
                ->connectTimeout(min(3, (int) config('sso.http_timeout')))
                ->acceptJson()
                ->get($url, array_filter([
                    'organization_id' => $organizationId,
                    'branch_id' => $branchId,
                ]));
        } catch (ConnectionException $exception) {
            throw new SsoException('Permission service is temporarily unreachable.', previous: $exception);
        }

        if (! $response->successful()) {
            throw new SsoException("Permission fetch failed ({$response->status()}) from {$url}.");
        }

        $data = $response->json();
        if (! is_array($data)) {
            throw new SsoException('Permission service returned a malformed response.');
        }

        $permissions = $data['permissions'] ?? null;
        $roles = $data['roles'] ?? null;
        $authoritative = $data['authoritative'] ?? null;

        if (! is_array($permissions)
            || ! array_is_list($permissions)
            || collect($permissions)->contains(fn (mixed $permission): bool => ! is_string($permission) || $permission === '')
            || ! is_array($roles)
            || ! array_is_list($roles)
            || collect($roles)->contains(fn (mixed $role): bool => ! $this->isValidRole($role))
            || ! is_bool($authoritative)
            || (isset($data['service_access']) && ! is_array($data['service_access']))
            || (isset($data['contract_version']) && ! is_string($data['contract_version']))
            || (isset($data['evaluated_at']) && ! is_string($data['evaluated_at']))) {
            throw new SsoException('Permission service returned a malformed response.');
        }

        return [
            'permissions' => $permissions,
            'roles' => $roles,
            'service_access' => is_array($data['service_access'] ?? null) ? $data['service_access'] : [],
            'contract_version' => is_string($data['contract_version'] ?? null) ? $data['contract_version'] : null,
            'evaluated_at' => is_string($data['evaluated_at'] ?? null) ? $data['evaluated_at'] : null,
            'authoritative' => $authoritative,
        ];
    }

    private function isValidRole(mixed $role): bool
    {
        if (is_string($role)) {
            return $role !== '';
        }

        if (! is_array($role)) {
            return false;
        }

        $identifier = $role['role'] ?? $role['slug'] ?? null;

        return is_string($identifier) && $identifier !== '';
    }

    /**
     * Drop every cached permission list for a bearer (all org/branch
     * contexts). Called on local logout and back-channel logout so a revoked
     * token cannot keep answering Gate checks from cache.
     */
    public static function forgetForTokenHash(string $tokenHash): void
    {
        $store = SsoCache::store();
        $indexKey = SsoCache::key('perms-index:'.$tokenHash);

        foreach ((array) $store->pull($indexKey, []) as $key) {
            if (is_string($key)) {
                $store->forget($key);
            }
        }
    }

    /** Track which permission keys exist for a token, for later invalidation. */
    private function indexKey(string $tokenHash, string $key): void
    {
        $store = SsoCache::store();
        $indexKey = SsoCache::key('perms-index:'.$tokenHash);
        $index = (array) $store->get($indexKey, []);

        if (! in_array($key, $index, true)) {
            $index[] = $key;
            $store->put($indexKey, $index, (int) config('sso.permissions_ttl', 300));
        }
    }

    /** @return Collection<int, string> */
    public function permissionsFor(string $accessToken, string $organizationId, ?string $branchId = null): Collection
    {
        return collect($this->fetch($accessToken, $organizationId, $branchId)['permissions']);
    }

    /**
     * Read the permission list for an AUTHORIZATION DECISION — resilient by
     * design. When the platform is briefly unreachable a Gate check or the
     * Sso facade must not blow up the page (the SsoException is renderable and
     * would 302 the whole response to the login-failure destination). Instead
     * we fail CLOSED: log a warning and return an empty list, so the missing
     * permission is denied rather than the user bounced. Set
     * `sso.permissions.strict` to rethrow (e.g. to surface outages loudly in a
     * job) — the raw fetch()/permissionsFor() always throw for callers that
     * want to handle it themselves.
     *
     * @return array{permissions: Collection<int, string>, roles: list<mixed>, service_access: array<string, mixed>, contract_version: ?string, evaluated_at: ?string, authoritative: bool}
     */
    public function resolveFor(string $accessToken, string $organizationId, ?string $branchId = null, bool $fresh = false): array
    {
        try {
            $result = $fresh
                ? $this->fetchFresh($accessToken, $organizationId, $branchId)
                : $this->fetch($accessToken, $organizationId, $branchId);

            return [
                'permissions' => collect($result['permissions']),
                'roles' => $result['roles'],
                'service_access' => $result['service_access'],
                'contract_version' => $result['contract_version'],
                'evaluated_at' => $result['evaluated_at'],
                'authoritative' => $result['authoritative'],
            ];
        } catch (SsoException $exception) {
            if ((bool) config('sso.permissions.strict', false)) {
                throw $exception;
            }

            Log::warning('SSO permission fetch failed — denying (fail-closed): '.$exception->getMessage());

            return [
                'permissions' => collect(),
                'roles' => [],
                'service_access' => [],
                'contract_version' => null,
                'evaluated_at' => null,
                'authoritative' => false,
            ];
        }
    }
}
