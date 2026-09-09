<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Dxs\Auth\Exceptions\SsoException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use stdClass;
use Throwable;

/**
 * Verifies a platform-issued access token (RFC 9068 `at+jwt`, RS256):
 * signature against the JWKS, plus `iss` / `aud` / `exp`. Returns the claims.
 */
final class JwtVerifier
{
    public function __construct(private readonly OidcDiscovery $discovery) {}

    /** @return array<string, mixed> validated claims */
    public function verify(string $jwt): array
    {
        $this->assertAccessTokenType($jwt);

        return $this->verifyForAudience($jwt, (string) config('sso.service_slug'));
    }

    /** @return array<string, mixed> validated ID-token claims */
    public function verifyIdToken(string $jwt, string $expectedNonce): array
    {
        // OIDC ID tokens target the relying party's client_id. Access tokens
        // continue to target the resource server's service_slug in verify().
        $expectedAudience = (string) config('sso.client_id');
        if ($expectedAudience === '') {
            throw new SsoException('SSO client ID is not configured.');
        }

        $type = $this->header($jwt)['typ'] ?? null;
        if (is_string($type) && strcasecmp($type, 'at+jwt') === 0) {
            throw new SsoException('SSO ID token must not be an access token.');
        }

        $claims = $this->verifyForAudience($jwt, $expectedAudience);

        $nonce = $claims['nonce'] ?? null;
        if ($expectedNonce === '' || ! is_string($nonce) || ! hash_equals($expectedNonce, $nonce)) {
            throw new SsoException('SSO ID token nonce mismatch.');
        }

        $audiences = is_array($claims['aud']) ? $claims['aud'] : [$claims['aud']];
        $authorizedParty = $claims['azp'] ?? null;
        if ((count($audiences) > 1 || $authorizedParty !== null)
            && (! is_string($authorizedParty) || ! hash_equals($expectedAudience, $authorizedParty))
        ) {
            throw new SsoException('SSO ID token authorized party mismatch.');
        }

        return $claims;
    }

    /** @return array<string, mixed> validated OIDC Back-Channel Logout token claims */
    public function verifyLogoutToken(string $jwt): array
    {
        $claims = $this->verifyForAudience($jwt, (string) config('sso.client_id'), false);
        $events = $claims['events'] ?? null;
        $backChannelEvent = 'http://schemas.openid.net/event/backchannel-logout';

        if ((! is_array($events) && ! $events instanceof stdClass)
            || ! array_key_exists($backChannelEvent, (array) $events)
        ) {
            throw new SsoException('SSO logout token is missing the back-channel logout event.');
        }
        if (array_key_exists('nonce', $claims)) {
            throw new SsoException('SSO logout token must not contain a nonce.');
        }

        $jwtId = $claims['jti'] ?? null;
        $sessionId = $claims['sid'] ?? null;
        $subject = $claims['sub'] ?? null;
        if (! is_string($jwtId) || $jwtId === '') {
            throw new SsoException('SSO logout token has no identifier.');
        }
        if ((! is_string($sessionId) || $sessionId === '')
            && (! is_string($subject) || $subject === '')
        ) {
            throw new SsoException('SSO logout token has neither a session nor a subject.');
        }

        return $claims;
    }

    /** @return array<string, mixed> */
    private function verifyForAudience(string $jwt, string $expectedAudience, bool $requireSubject = true): array
    {
        JWT::$leeway = (int) config('sso.leeway');

        try {
            $jwks = $this->discovery->jwks();
            $keyId = $this->keyId($jwt);

            if ($keyId !== null && ! $this->containsKeyId($jwks, $keyId)) {
                $jwks = $this->discovery->jwks(fresh: true);
            }

            $keys = JWK::parseKeySet($jwks);
            $claims = (array) JWT::decode($jwt, $keys); // validates signature + exp/nbf/iat
        } catch (Throwable $e) {
            throw new SsoException('SSO token signature/expiry validation failed: '.$e->getMessage(), previous: $e);
        }

        $expectedIssuer = rtrim((string) config('sso.issuer'), '/');
        $issuer = $claims['iss'] ?? null;
        if (! is_string($issuer) || rtrim($issuer, '/') !== $expectedIssuer) {
            throw new SsoException('SSO token issuer mismatch.');
        }

        $audience = $claims['aud'] ?? null;
        $audiences = is_array($audience) ? array_values($audience) : [$audience];
        if ($audiences === []
            || array_filter($audiences, fn (mixed $value): bool => ! is_string($value)) !== []
            || ! in_array($expectedAudience, $audiences, true)
        ) {
            throw new SsoException('SSO token audience is not this service.');
        }

        if ($requireSubject && (! isset($claims['sub']) || ! is_string($claims['sub']) || $claims['sub'] === '')) {
            throw new SsoException('SSO token has no subject.');
        }

        return $claims;
    }

    /**
     * RFC 9068 §4 — a JWT access token MUST carry `typ: at+jwt` (compared
     * case-insensitively); reject every other media type so an ID token or a
     * logout token can never be replayed as an access token. Applies only to
     * the access-token path — ID and logout tokens keep their own types.
     */
    private function assertAccessTokenType(string $jwt): void
    {
        $header = $this->header($jwt);
        $type = is_array($header) ? ($header['typ'] ?? null) : null;

        if (! is_string($type) || strcasecmp($type, 'at+jwt') !== 0) {
            throw new SsoException('SSO access token is not an RFC 9068 at+jwt token.');
        }
    }

    /** @return array<string, mixed>|null */
    private function header(string $jwt): ?array
    {
        $segments = explode('.', $jwt);
        if (count($segments) !== 3) {
            return null;
        }

        $header = json_decode(JWT::urlsafeB64Decode($segments[0]), true);

        return is_array($header) ? $header : null;
    }

    private function keyId(string $jwt): ?string
    {
        $keyId = $this->header($jwt)['kid'] ?? null;

        return is_string($keyId) && $keyId !== '' ? $keyId : null;
    }

    /** @param array<string, mixed> $jwks */
    private function containsKeyId(array $jwks, string $keyId): bool
    {
        foreach ($jwks['keys'] ?? [] as $key) {
            if (is_array($key) && ($key['kid'] ?? null) === $keyId) {
                return true;
            }
        }

        return false;
    }
}
