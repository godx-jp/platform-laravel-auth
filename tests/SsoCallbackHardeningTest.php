<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\JwtFactory;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use Orchestra\Testbench\TestCase;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Hardening details of the callback's session/cookie handling: the bearer
 * cookie's browser-facing attributes and the token-lifetime edge cases that
 * drive its expiry.
 */
final class SsoCallbackHardeningTest extends TestCase
{
    private const ORGANIZATION_CONTEXT_ID = '9f79d9ee-d735-4673-a80d-c11339f252be';

    private JwtFactory $jwt;

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('session.driver', 'array');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.client_secret', 'consumer-a-secret');
        $app['config']->set('sso.redirect_uri', 'https://consumer-a.example.test/auth/callback');
        $app['config']->set('sso.after_login', '/home');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
        $this->jwt = new JwtFactory;
        $this->app->instance(ProvisionsUsers::class, new StaticProvisioner);
    }

    public function test_the_bearer_cookie_is_http_only_lax_and_path_scoped(): void
    {
        $this->completeCallback(['expires_in' => 900]);

        $cookie = $this->lastTokenCookie();

        $this->assertTrue($cookie->isHttpOnly());
        $this->assertSame('lax', $cookie->getSameSite());
        $this->assertSame('/', $cookie->getPath());
    }

    public function test_the_cookie_lifetime_follows_the_token_expiry(): void
    {
        $this->completeCallback(['expires_in' => 900]);

        $this->assertEqualsWithDelta(
            now()->addMinutes(15)->timestamp,
            $this->lastTokenCookie()->getExpiresTime(),
            10,
        );
    }

    public function test_a_zero_or_negative_expiry_still_produces_a_usable_short_cookie(): void
    {
        $this->completeCallback(['expires_in' => 0]);

        // Clamped to the one-minute floor — never an already-expired cookie.
        $this->assertEqualsWithDelta(
            now()->addMinute()->timestamp,
            $this->lastTokenCookie()->getExpiresTime(),
            10,
        );
    }

    public function test_a_missing_expiry_defaults_to_the_platform_ttl(): void
    {
        $this->completeCallback([]);

        $this->assertEqualsWithDelta(
            now()->addMinutes(15)->timestamp,
            $this->lastTokenCookie()->getExpiresTime(),
            10,
        );
    }

    private TestResponse $lastResponse;

    /** @param array<string, mixed> $tokenExtras */
    private function completeCallback(array $tokenExtras): void
    {
        $accessToken = $this->jwt->token([
            'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
        ]);
        $idToken = $this->jwt->idToken(['nonce' => 'bound-nonce']);

        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
            'https://id.example.test/api/sso/token' => Http::response(array_merge([
                'access_token' => $accessToken,
                'id_token' => $idToken,
                'token_type' => 'Bearer',
            ], $tokenExtras)),
            'https://id.example.test/.well-known/jwks.json' => Http::response($this->jwt->jwks()),
        ]);

        $this->lastResponse = $this->withSession([
            'sso.transactions' => [
                'bound-state' => [
                    'verifier' => 'bound-verifier',
                    'nonce' => 'bound-nonce',
                    'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
                    'return' => null,
                    'created_at' => now()->timestamp,
                ],
            ],
        ])->get('/auth/callback?code=authorization-code&state=bound-state');

        $this->lastResponse->assertRedirect('/home');
    }

    private function lastTokenCookie(): Cookie
    {
        $cookie = collect($this->lastResponse->headers->getCookies())
            ->first(fn ($candidate) => $candidate->getName() === 'token');

        $this->assertNotNull($cookie, 'The bearer cookie must be present.');

        return $cookie;
    }
}

final class StaticProvisioner implements ProvisionsUsers
{
    public function provision(array $claims, array $tokens): Authenticatable
    {
        return new GenericUser(['id' => $claims['sub'] ?? 'user']);
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        return null;
    }
}
