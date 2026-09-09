<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\JwtFactory;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * Downstream contract coverage for the two organization claim shapes the IdP
 * has shipped: the legacy `organization_context_id` (console organization id,
 * mirrored from the authorize request) and the current platform's
 * `organization_id` (the service instance's internal platform organization
 * id, RFC 9068 service tokens). Found by wiring a real downstream consumer
 * (gino-cloud) against the live platform IdP: tokens carry only
 * `organization_id`, so the legacy-only check rejected every login.
 */
final class SsoCallbackOrganizationClaimTest extends TestCase
{
    private const ORGANIZATION_CONTEXT_ID = '9f79d9ee-d735-4673-a80d-c11339f252be';

    private const PLATFORM_ORGANIZATION_ID = '019f6ece-2629-730a-ab0b-0f323d4e2e02';

    private JwtFactory $jwt;

    private ClaimRecordingProvisioner $provisioner;

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
        $this->provisioner = new ClaimRecordingProvisioner;
        $this->app->instance(ProvisionsUsers::class, $this->provisioner);
    }

    public function test_it_accepts_a_platform_service_token_with_the_organization_id_claim(): void
    {
        config()->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);

        $this->fakeOidc(
            $this->jwt->token(['organization_id' => self::PLATFORM_ORGANIZATION_ID]),
            $this->jwt->idToken(['nonce' => 'bound-nonce']),
        );

        $response = $this->withSession($this->boundSession())
            ->get('/auth/callback?code=authorization-code&state=bound-state');

        $response->assertRedirect('/protected?tab=security');
        $this->assertSame('user-1', $this->provisioner->claims['sub']);
    }

    public function test_it_rejects_an_organization_id_claim_that_does_not_match_the_configured_organization(): void
    {
        config()->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);

        $this->fakeOidc(
            $this->jwt->token(['organization_id' => '0198aaaa-bbbb-7ccc-8ddd-eeeeffff0000']),
            $this->jwt->idToken(['nonce' => 'bound-nonce']),
        );

        $this->expectCallbackFailure('organization does not match');
    }

    public function test_the_organization_id_fallback_requires_explicit_configuration(): void
    {
        $this->fakeOidc(
            $this->jwt->token(['organization_id' => self::PLATFORM_ORGANIZATION_ID]),
            $this->jwt->idToken(['nonce' => 'bound-nonce']),
        );

        $this->expectCallbackFailure('missing a verifiable organization claim');
    }

    public function test_it_rejects_a_token_with_no_organization_claim(): void
    {
        config()->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);

        $this->fakeOidc(
            $this->jwt->token(),
            $this->jwt->idToken(['nonce' => 'bound-nonce']),
        );

        $this->expectCallbackFailure('missing a verifiable organization claim');
    }

    public function test_the_legacy_organization_context_claim_takes_precedence_and_must_match_the_transaction(): void
    {
        config()->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);

        $this->fakeOidc(
            $this->jwt->token([
                'organization_context_id' => '3efb1df0-1814-480c-9566-42d339758da8',
                'organization_id' => self::PLATFORM_ORGANIZATION_ID,
            ]),
            $this->jwt->idToken(['nonce' => 'bound-nonce']),
        );

        $this->expectCallbackFailure('organization context does not match');
    }

    public function test_profile_claims_from_the_id_token_reach_the_provisioner(): void
    {
        config()->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);

        $this->fakeOidc(
            $this->jwt->token(['organization_id' => self::PLATFORM_ORGANIZATION_ID]),
            $this->jwt->idToken([
                'nonce' => 'bound-nonce',
                'name' => 'Famgia Info',
                'email' => 'info@example.test',
            ]),
        );

        $this->withSession($this->boundSession())
            ->get('/auth/callback?code=authorization-code&state=bound-state')
            ->assertRedirect('/protected?tab=security');

        $this->assertSame('Famgia Info', $this->provisioner->claims['name']);
        $this->assertSame('info@example.test', $this->provisioner->claims['email']);
    }

    public function test_access_token_profile_claims_are_not_overwritten_by_the_id_token(): void
    {
        config()->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);

        $this->fakeOidc(
            $this->jwt->token([
                'organization_id' => self::PLATFORM_ORGANIZATION_ID,
                'name' => 'Access Token Name',
                'email' => 'access@example.test',
            ]),
            $this->jwt->idToken([
                'nonce' => 'bound-nonce',
                'name' => 'Id Token Name',
                'email' => 'id@example.test',
            ]),
        );

        $this->withSession($this->boundSession())
            ->get('/auth/callback?code=authorization-code&state=bound-state')
            ->assertRedirect('/protected?tab=security');

        $this->assertSame('Access Token Name', $this->provisioner->claims['name']);
        $this->assertSame('access@example.test', $this->provisioner->claims['email']);
    }

    /** @return array<string, mixed> */
    private function boundSession(): array
    {
        return [
            'sso.transactions' => [
                'bound-state' => [
                    'verifier' => 'bound-verifier',
                    'nonce' => 'bound-nonce',
                    'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
                    'return' => '/protected?tab=security',
                    'created_at' => now()->timestamp,
                ],
            ],
        ];
    }

    private function fakeOidc(string $accessToken, ?string $idToken = null): void
    {
        $tokens = [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 900,
        ];
        if ($idToken !== null) {
            $tokens['id_token'] = $idToken;
        }

        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
            'https://id.example.test/api/sso/token' => Http::response($tokens),
            'https://id.example.test/.well-known/jwks.json' => Http::response($this->jwt->jwks()),
        ]);
    }

    private function expectCallbackFailure(string $message): void
    {
        $this->withoutExceptionHandling();
        $this->expectException(SsoException::class);
        $this->expectExceptionMessage($message);

        try {
            $this->withSession($this->boundSession())
                ->get('/auth/callback?code=authorization-code&state=bound-state');
        } finally {
            $this->assertSame([], $this->provisioner->claims);
        }
    }
}

final class ClaimRecordingProvisioner implements ProvisionsUsers
{
    /** @var array<string, mixed> */
    public array $claims = [];

    /** @var array<string, mixed> */
    public array $tokens = [];

    public function provision(array $claims, array $tokens): Authenticatable
    {
        $this->claims = $claims;
        $this->tokens = $tokens;

        return new GenericUser(['id' => $claims['sub'], 'name' => 'Package User']);
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        return null;
    }
}
