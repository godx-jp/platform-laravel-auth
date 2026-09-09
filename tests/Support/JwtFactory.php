<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests\Support;

use Firebase\JWT\JWT;

final class JwtFactory
{
    private const DEFAULT_KEY_ID = 'package-test-key';

    private string $privateKey;

    /** @var array<string, mixed> */
    private array $jwk;

    public function __construct(private readonly string $keyId = self::DEFAULT_KEY_ID)
    {
        $key = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false || ! openssl_pkey_export($key, $privateKey)) {
            throw new \RuntimeException('Unable to create the test RSA key.');
        }

        $details = openssl_pkey_get_details($key);
        if (! is_array($details) || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new \RuntimeException('Unable to read the test RSA key.');
        }

        $this->privateKey = $privateKey;
        $this->jwk = [
            'kty' => 'RSA',
            'kid' => $this->keyId,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => $this->base64Url($details['rsa']['n']),
            'e' => $this->base64Url($details['rsa']['e']),
        ];
    }

    /**
     * @param  array<string, mixed>  $claims
     * @param  array<string, mixed>  $headers
     */
    public function token(array $claims = [], ?string $keyId = null, array $headers = []): string
    {
        $now = time();

        return JWT::encode(array_merge([
            'iss' => 'https://id.example.test',
            'aud' => 'consumer-a',
            'sub' => 'user-1',
            'iat' => $now,
            'nbf' => $now - 1,
            'exp' => $now + 300,
        ], $claims), $this->privateKey, 'RS256', $keyId ?? $this->keyId, array_merge(['typ' => 'at+jwt'], $headers));
    }

    /** @param array<string, mixed> $claims */
    public function idToken(array $claims = []): string
    {
        return $this->token(array_merge(['aud' => 'consumer-a-client'], $claims), headers: ['typ' => 'JWT']);
    }

    /** @return array{keys: array<int, array<string, mixed>>} */
    public function jwks(): array
    {
        return ['keys' => [$this->jwk]];
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
