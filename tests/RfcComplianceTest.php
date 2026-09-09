<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\JwtVerifier;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\JwtFactory;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Spec-conformance details pinned one by one:
 *
 * - RFC 9068 §4      — access tokens MUST be `typ: at+jwt`; anything else is
 *                      rejected so ID/logout tokens cannot double as ATs.
 * - RFC 6750 §3      — 401 responses carry a WWW-Authenticate challenge, with
 *                      `error="invalid_token"` only when a token was presented.
 * - OIDC Back-Channel Logout §2.8 — responses carry Cache-Control: no-store.
 * - OIDC RP-Initiated Logout — the end-session redirect identifies the RP and
 *                      its post-logout destination.
 * - Authorization-request TTL — pending transactions expire and are pruned.
 */
final class RfcComplianceTest extends TestCase
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
        $app['config']->set('sso.after_logout', '/goodbye');
        $app['config']->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
        $this->jwt = new JwtFactory;
        $this->app->instance(ProvisionsUsers::class, new PassthroughProvisioner);
    }

    // ---- RFC 9068: access-token type ------------------------------------

    public function test_an_at_jwt_typed_access_token_verifies(): void
    {
        $this->fakeJwksOnly();

        $claims = $this->app->make(JwtVerifier::class)
            ->verify($this->jwt->token(['organization_context_id' => self::ORGANIZATION_CONTEXT_ID]));

        $this->assertSame('user-1', $claims['sub']);
    }

    public function test_the_access_token_type_is_compared_case_insensitively(): void
    {
        $this->fakeJwksOnly();

        $claims = $this->app->make(JwtVerifier::class)
            ->verify($this->jwt->token([], headers: ['typ' => 'AT+JWT']));

        $this->assertSame('user-1', $claims['sub']);
    }

    #[DataProvider('nonAccessTokenTypes')]
    public function test_non_at_jwt_media_types_are_rejected_as_access_tokens(string $type): void
    {
        $this->fakeJwksOnly();

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('not an RFC 9068 at+jwt token');

        $this->app->make(JwtVerifier::class)
            ->verify($this->jwt->token([], headers: ['typ' => $type]));
    }

    /** @return iterable<string, array{string}> */
    public static function nonAccessTokenTypes(): iterable
    {
        yield 'plain JWT (an ID token)' => ['JWT'];
        yield 'logout token' => ['logout+jwt'];
        yield 'empty' => [''];
    }

    public function test_id_tokens_keep_their_own_type_and_still_verify(): void
    {
        $this->fakeJwksOnly();

        $claims = $this->app->make(JwtVerifier::class)
            ->verifyIdToken($this->jwt->idToken(['nonce' => 'n-1']), 'n-1');

        $this->assertSame('user-1', $claims['sub']);
    }

    // ---- RFC 6750: WWW-Authenticate on 401 ------------------------------

    public function test_a_bare_401_challenge_when_no_token_was_presented(): void
    {
        $this->withProtectedRoute();

        $this->getJson('/protected')
            ->assertUnauthorized()
            ->assertHeader('WWW-Authenticate', 'Bearer realm="sso"');
    }

    public function test_an_invalid_token_401_names_the_error(): void
    {
        config()->set('app.env', 'production');
        $this->withProtectedRoute();
        $this->fakeJwksOnly();

        $this->withHeader('Authorization', 'Bearer not-a-jwt')
            ->getJson('/protected')
            ->assertUnauthorized()
            ->assertHeader('WWW-Authenticate', 'Bearer realm="sso", error="invalid_token"');
    }

    // ---- Back-channel logout: Cache-Control -----------------------------

    public function test_backchannel_logout_success_is_uncacheable(): void
    {
        $this->fakeJwksOnly();

        $logoutToken = $this->jwt->token([
            'aud' => 'consumer-a-client',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => (object) []],
            'jti' => 'jti-1',
            'sid' => 'sid-1',
        ]);

        $this->post('/auth/backchannel-logout', ['logout_token' => $logoutToken])
            ->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private');
    }

    public function test_backchannel_logout_failures_are_uncacheable_too(): void
    {
        $this->post('/auth/backchannel-logout', [])
            ->assertStatus(400)
            ->assertHeader('Cache-Control', 'no-store, private');

        $this->post('/auth/backchannel-logout', ['logout_token' => 'garbage'])
            ->assertStatus(400)
            ->assertHeader('Cache-Control', 'no-store, private');
    }

    // ---- RP-initiated logout parameters ---------------------------------

    public function test_the_end_session_redirect_identifies_the_rp_and_its_post_logout_destination(): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
                'end_session_endpoint' => 'https://id.example.test/sso/logout',
            ]),
        ]);

        $response = $this->post('/auth/logout');

        $location = (string) $response->headers->get('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        $this->assertStringStartsWith('https://id.example.test/sso/logout?', $location);
        $this->assertSame('consumer-a-client', $query['client_id']);
        $this->assertSame(url('/goodbye'), $query['post_logout_redirect_uri']);
    }

    // ---- Authorization-transaction TTL ----------------------------------

    public function test_an_expired_transaction_is_rejected_at_the_callback(): void
    {
        Http::fake();

        $response = $this->withSession([
            'sso.transactions' => [
                'old-state' => [
                    'verifier' => 'v',
                    'nonce' => 'n',
                    'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
                    'return' => null,
                    'created_at' => now()->subMinutes(11)->timestamp,
                ],
            ],
        ])->get('/auth/callback?code=authorization-code&state=old-state');

        $response->assertRedirect('/goodbye');
        $response->assertSessionHas('sso.error', 'SSO sign-in took too long — please try again.');
        Http::assertNothingSent();
    }

    public function test_a_transaction_within_the_ttl_still_completes(): void
    {
        $accessToken = $this->jwt->token(['organization_context_id' => self::ORGANIZATION_CONTEXT_ID]);
        $idToken = $this->jwt->idToken(['nonce' => 'n']);
        $this->fakeFullIdp($accessToken, $idToken);

        $this->withSession([
            'sso.transactions' => [
                'fresh-state' => [
                    'verifier' => 'v',
                    'nonce' => 'n',
                    'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
                    'return' => null,
                    'created_at' => now()->subMinutes(9)->timestamp,
                ],
            ],
        ])->get('/auth/callback?code=authorization-code&state=fresh-state')
            ->assertRedirect('/home');
    }

    public function test_starting_a_new_flow_prunes_expired_transactions_but_keeps_fresh_ones(): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
        ]);

        $this->withSession([
            'sso.transactions' => [
                'stale' => ['verifier' => 'v', 'nonce' => 'n', 'organization_context_id' => self::ORGANIZATION_CONTEXT_ID, 'return' => null, 'created_at' => now()->subHour()->timestamp],
                'fresh' => ['verifier' => 'v', 'nonce' => 'n', 'organization_context_id' => self::ORGANIZATION_CONTEXT_ID, 'return' => null, 'created_at' => now()->subMinute()->timestamp],
            ],
        ])->get('/auth/redirect');

        $transactions = session('sso.transactions');

        $this->assertArrayNotHasKey('stale', $transactions);
        $this->assertArrayHasKey('fresh', $transactions);
        $this->assertCount(2, $transactions); // fresh + the newly minted one
    }

    // ---- helpers ---------------------------------------------------------

    private function withProtectedRoute(): void
    {
        $this->app['router']->get('/protected', fn () => response()->json(['ok' => true]))
            ->middleware('sso.auth');
    }

    private function fakeJwksOnly(): void
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

    private function fakeFullIdp(string $accessToken, string $idToken): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
            'https://id.example.test/api/sso/token' => Http::response([
                'access_token' => $accessToken,
                'id_token' => $idToken,
                'token_type' => 'Bearer',
                'expires_in' => 900,
            ]),
            'https://id.example.test/.well-known/jwks.json' => Http::response($this->jwt->jwks()),
        ]);
    }
}

final class PassthroughProvisioner implements ProvisionsUsers
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
