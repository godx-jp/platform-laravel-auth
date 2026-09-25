<?php

declare(strict_types=1);

namespace Dxs\Auth\Support;

use Dxs\Auth\Exceptions\SsoConfigurationException;
use Illuminate\Support\Str;

/**
 * Fail fast when the two organization env values for a fixed downstream tenant
 * are misconfigured (only one set, identical values, or missing the internal id
 * the current platform stamps into service tokens).
 */
final class OrganizationConfigurationGuard
{
    /**
     * @return list<string>
     */
    public static function diagnose(): array
    {
        $contextId = self::organizationContextId();
        $internalId = self::organizationId();
        $allowSwitching = (bool) config('sso.allow_organization_switching', false);
        $findings = [];

        if ($contextId === '' && $internalId === '') {
            $findings[] = 'Neither SSO_ORGANIZATION_CONTEXT_ID nor SSO_ORGANIZATION_ID is set.';
            if ($allowSwitching) {
                $findings[] = 'Multi-tenant launches may pass organization_context_id on /auth/redirect; SSO_ORGANIZATION_ID is still required for current platform service tokens at callback.';
            } else {
                $findings[] = 'Single-tenant services should set both values (see docs/onboarding.md Step 2).';
            }

            return $findings;
        }

        if ($contextId !== '') {
            $findings[] = 'SSO_ORGANIZATION_CONTEXT_ID (console org → /sso/authorize): '.$contextId;
        } else {
            $findings[] = 'SSO_ORGANIZATION_CONTEXT_ID is not set (console organization id for authorize).';
        }

        if ($internalId !== '') {
            $findings[] = 'SSO_ORGANIZATION_ID (internal organizations.id → token organization_id claim): '.$internalId;
        } else {
            $findings[] = 'SSO_ORGANIZATION_ID is not set (internal platform Organization id for token validation).';
        }

        foreach (self::misconfigurationMessages($contextId, $internalId, $allowSwitching) as $message) {
            $findings[] = 'Problem: '.$message;
        }

        foreach (self::advisoryMessages($contextId, $internalId, $allowSwitching) as $message) {
            $findings[] = 'Warning: '.$message;
        }

        if ($contextId !== '' && $internalId !== '' && self::misconfigurationMessages($contextId, $internalId, $allowSwitching) === []) {
            $findings[] = 'Both organization values are set and differ — expected for the current platform.';
        }

        return $findings;
    }

    public static function assertReadyForAuthorize(): void
    {
        $contextId = self::organizationContextId();
        $internalId = self::organizationId();
        $allowSwitching = (bool) config('sso.allow_organization_switching', false);

        foreach (self::misconfigurationMessages($contextId, $internalId, $allowSwitching) as $message) {
            throw new SsoConfigurationException($message);
        }
    }

    public static function consumerLooksConfigured(): bool
    {
        return trim((string) config('sso.client_id', '')) !== ''
            && trim((string) config('sso.client_secret', '')) !== '';
    }

    public static function organizationContextId(): string
    {
        return trim((string) config('sso.organization_context_id', ''));
    }

    public static function organizationId(): string
    {
        return trim((string) config('sso.organization_id', ''));
    }

    /**
     * Only mistakes that are wrong under EVERY platform contract. A missing value is
     * NOT one of them: the callback prefers `organization_context_id` and falls back to
     * `organization_id`, so which of the two a consumer needs depends on the token the
     * IdP issues — `sso:doctor` reports it as a warning instead of refusing to log in.
     *
     * @return list<string>
     */
    private static function misconfigurationMessages(string $contextId, string $internalId, bool $allowSwitching): array
    {
        $messages = [];

        if ($contextId !== '' && $internalId !== '' && hash_equals($contextId, $internalId)) {
            $messages[] = 'SSO_ORGANIZATION_CONTEXT_ID and SSO_ORGANIZATION_ID are identical. They must be two different UUIDs for the same tenant (console organization id vs internal organizations.id). Swapping or reusing one value for both is the most common onboarding mistake.';
        }

        if ($contextId !== '' && ! Str::isUuid($contextId)) {
            $messages[] = 'SSO_ORGANIZATION_CONTEXT_ID is not a valid UUID.';
        }

        if ($internalId !== '' && ! Str::isUuid($internalId)) {
            $messages[] = 'SSO_ORGANIZATION_ID is not a valid UUID.';
        }

        return $messages;
    }

    /**
     * Advisory only — printed by `sso:doctor`, never thrown.
     *
     * @return list<string>
     */
    private static function advisoryMessages(string $contextId, string $internalId, bool $allowSwitching): array
    {
        $messages = [];

        if ($contextId !== '' && $internalId === '') {
            $messages[] = 'SSO_ORGANIZATION_ID is not set. Fine when the IdP stamps organization_context_id into the token; if callback fails with "token organization … does not match", set it to the internal organizations.id (docs/onboarding.md Step 2).';
        }

        if ($internalId !== '' && $contextId === '' && ! $allowSwitching) {
            $messages[] = 'SSO_ORGANIZATION_CONTEXT_ID is not set and organization switching is off — authorize requests will carry no organization. Set it to the console org id shown in the platform UI.';
        }

        return $messages;
    }
}
