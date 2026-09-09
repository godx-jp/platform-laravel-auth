<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\JwtVerifier;
use Dxs\Auth\Services\OidcDiscovery;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\JwtFactory;
use Firebase\JWT\JWT;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class JwtVerifierTest extends TestCase
{
    private JwtFactory $jwt;

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.leeway', 0);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
        $this->jwt = new JwtFactory;
        $this->fakeDiscoveryAndJwks();
    }

    public function test_it_verifies_signature_expiry_issuer_audience_subject_and_nonce(): void
    {
        $claims = $this->app->make(JwtVerifier::class)->verifyIdToken(
            $this->jwt->idToken(['nonce' => 'bound-nonce']),
            'bound-nonce',
        );

        $this->assertSame('user-1', $claims['sub']);
        $this->assertSame('consumer-a-client', $claims['aud']);
    }

    /** @param array<string, mixed> $claims */
    #[DataProvider('invalidClaimSets')]
    public function test_it_fails_closed_for_invalid_registered_claims(array $claims, string $message): void
    {
        $this->expectException(SsoException::class);
        $this->expectExceptionMessage($message);

        $this->app->make(JwtVerifier::class)->verify($this->jwt->token($claims));
    }

    /** @return array<string, array{array<string, mixed>, string}> */
    public static function invalidClaimSets(): array
    {
        return [
            'expired' => [['exp' => time() - 60], 'signature/expiry validation failed'],
            'future not-before' => [['nbf' => time() + 60], 'signature/expiry validation failed'],
            'wrong issuer' => [['iss' => 'https://attacker.example'], 'issuer mismatch'],
            'wrong audience' => [['aud' => 'consumer-b'], 'audience is not this service'],
            'missing subject' => [['sub' => ''], 'has no subject'],
        ];
    }

    public function test_it_rejects_a_token_signed_by_an_untrusted_key(): void
    {
        $attacker = new JwtFactory;

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('signature/expiry validation failed');

        $this->app->make(JwtVerifier::class)->verify($attacker->token());
    }

    public function test_it_rejects_a_token_without_a_matching_key_id(): void
    {
        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('signature/expiry validation failed');

        $this->app->make(JwtVerifier::class)->verify($this->jwt->token([], 'unknown-key'));
    }

    public function test_it_refreshes_jwks_once_when_a_rotated_key_id_is_seen(): void
    {
        $rotated = new JwtFactory('rotated-key');
        $jwksRequests = 0;

        Http::swap(new Factory);
        Http::fake(function ($request) use ($rotated, &$jwksRequests) {
            if (str_ends_with($request->url(), '/.well-known/openid-configuration')) {
                return Http::response([
                    'issuer' => 'https://id.example.test',
                    'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                    'token_endpoint' => 'https://id.example.test/api/sso/token',
                    'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
                ]);
            }

            $jwksRequests++;

            return Http::response($jwksRequests === 1 ? $this->jwt->jwks() : $rotated->jwks());
        });

        $this->app->make(OidcDiscovery::class)->jwks();
        $claims = $this->app->make(JwtVerifier::class)->verify($rotated->token());

        $this->assertSame('user-1', $claims['sub']);
        $this->assertSame(2, $jwksRequests);
    }

    public function test_it_bounds_unknown_key_refresh_to_one_request(): void
    {
        $jwksRequests = 0;

        Http::swap(new Factory);
        Http::fake(function ($request) use (&$jwksRequests) {
            if (str_ends_with($request->url(), '/.well-known/openid-configuration')) {
                return Http::response([
                    'issuer' => 'https://id.example.test',
                    'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                    'token_endpoint' => 'https://id.example.test/api/sso/token',
                    'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
                ]);
            }

            $jwksRequests++;

            return Http::response($this->jwt->jwks());
        });

        try {
            $this->app->make(JwtVerifier::class)->verify($this->jwt->token([], 'never-published'));
            $this->fail('Expected unknown signing key to fail.');
        } catch (SsoException) {
            $this->assertSame(2, $jwksRequests);
        }
    }

    public function test_it_rejects_algorithm_confusion_against_an_rsa_jwks(): void
    {
        $now = time();
        $token = JWT::encode([
            'iss' => 'https://id.example.test',
            'aud' => 'consumer-a',
            'sub' => 'attacker',
            'iat' => $now,
            'exp' => $now + 300,
        ], str_repeat('attacker-controlled-secret', 4), 'HS256', 'package-test-key', ['typ' => 'at+jwt']);

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('signature/expiry validation failed');

        $this->app->make(JwtVerifier::class)->verify($token);
    }

    public function test_it_rejects_an_id_token_when_the_nonce_is_missing_or_different(): void
    {
        foreach ([null, 'attacker-nonce', ['polluted']] as $nonce) {
            try {
                $this->app->make(JwtVerifier::class)->verifyIdToken(
                    $this->jwt->idToken(array_filter(['nonce' => $nonce])),
                    'bound-nonce',
                );
                $this->fail('Expected nonce validation to fail.');
            } catch (SsoException $exception) {
                $this->assertStringContainsString('nonce mismatch', $exception->getMessage());
            }
        }
    }

    public function test_it_enforces_authorized_party_for_multi_audience_id_tokens(): void
    {
        foreach ([
            ['aud' => ['consumer-a-client', 'consumer-b'], 'nonce' => 'bound-nonce'],
            ['aud' => ['consumer-a-client', 'consumer-b'], 'azp' => 'consumer-b', 'nonce' => 'bound-nonce'],
        ] as $claims) {
            try {
                $this->app->make(JwtVerifier::class)->verifyIdToken(
                    $this->jwt->idToken($claims),
                    'bound-nonce',
                );
                $this->fail('Expected authorized-party validation to fail.');
            } catch (SsoException $exception) {
                $this->assertStringContainsString('authorized party mismatch', $exception->getMessage());
            }
        }

        $valid = $this->app->make(JwtVerifier::class)->verifyIdToken(
            $this->jwt->idToken([
                'aud' => ['consumer-a-client', 'consumer-b'],
                'azp' => 'consumer-a-client',
                'nonce' => 'bound-nonce',
            ]),
            'bound-nonce',
        );
        $this->assertSame('consumer-a-client', $valid['azp']);
    }

    public function test_it_rejects_a_structurally_invalid_audience_without_type_coercion(): void
    {
        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('audience is not this service');

        $this->app->make(JwtVerifier::class)->verify($this->jwt->token([
            'aud' => ['consumer-a', ['polluted']],
        ]));
    }

    public function test_id_tokens_cannot_use_the_service_slug_as_their_audience(): void
    {
        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('audience is not this service');
        $this->app->make(JwtVerifier::class)->verifyIdToken(
            $this->jwt->idToken(['aud' => 'consumer-a', 'nonce' => 'bound-nonce']),
            'bound-nonce',
        );
    }

    public function test_access_tokens_still_require_the_service_slug_audience(): void
    {
        $verifier = $this->app->make(JwtVerifier::class);
        $this->assertSame('consumer-a', $verifier->verify($this->jwt->token())['aud']);
        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('audience is not this service');
        $verifier->verify($this->jwt->token(['aud' => 'consumer-a-client']));
    }

    public function test_an_access_token_cannot_be_substituted_for_an_id_token_even_with_matching_audience_and_nonce(): void
    {
        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('ID token must not be an access token');
        $this->app->make(JwtVerifier::class)->verifyIdToken(
            $this->jwt->token(['aud' => 'consumer-a-client', 'nonce' => 'bound-nonce']),
            'bound-nonce',
        );
    }

    public function test_an_id_token_cannot_be_substituted_for_an_access_token(): void
    {
        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('not an RFC 9068 at+jwt');
        $this->app->make(JwtVerifier::class)->verify($this->jwt->idToken(['aud' => 'consumer-a']));
    }

    public function test_single_audience_id_token_rejects_a_service_slug_authorized_party(): void
    {
        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('authorized party mismatch');
        $this->app->make(JwtVerifier::class)->verifyIdToken(
            $this->jwt->idToken(['nonce' => 'bound-nonce', 'azp' => 'consumer-a']),
            'bound-nonce',
        );
    }

    public function test_id_tokens_require_a_nonempty_configured_client_id(): void
    {
        config(['sso.client_id' => '']);
        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('client ID is not configured');
        $this->app->make(JwtVerifier::class)->verifyIdToken(
            $this->jwt->idToken(['aud' => '', 'nonce' => 'bound-nonce']),
            'bound-nonce',
        );
    }

    private function fakeDiscoveryAndJwks(): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
            'https://id.example.test/.well-known/jwks.json' => Http::response($this->jwt->jwks()),
        ]);
    }
}
