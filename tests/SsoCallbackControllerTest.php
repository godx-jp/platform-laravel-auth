<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\JwtFactory;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class SsoCallbackControllerTest extends TestCase
{
    private const ORGANIZATION_CONTEXT_ID = '9f79d9ee-d735-4673-a80d-c11339f252be';

    private JwtFactory $jwt;

    private RecordingProvisioner $provisioner;

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
        $this->provisioner = new RecordingProvisioner;
        $this->app->instance(ProvisionsUsers::class, $this->provisioner);
    }

    public function test_it_completes_a_bound_code_pkce_nonce_and_organization_transaction_once(): void
    {
        $accessToken = $this->jwt->token([
            'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
        ]);
        $idToken = $this->jwt->idToken(['nonce' => 'bound-nonce']);
        $this->fakeOidc($accessToken, $idToken);

        $response = $this->withSession($this->boundSession())
            ->get('/auth/callback?code=authorization-code&state=bound-state');

        $response->assertRedirect('/protected?tab=security');
        $response->assertCookie('token', $accessToken);
        $response->assertSessionMissing('sso.transactions.bound-state');
        $this->assertSame('user-1', $this->provisioner->claims['sub']);
        $this->assertSame($accessToken, $this->provisioner->tokens['access_token']);
        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://id.example.test/api/sso/token'
            && $request['grant_type'] === 'authorization_code'
            && $request['code'] === 'authorization-code'
            && $request['code_verifier'] === 'bound-verifier'
            && $request['redirect_uri'] === 'https://consumer-a.example.test/auth/callback');
    }

    public function test_unknown_state_does_not_consume_an_independent_transaction_or_contact_the_token_endpoint(): void
    {
        Http::fake();

        try {
            $this->withoutExceptionHandling()
                ->withSession($this->boundSession())
                ->get('/auth/callback?code=authorization-code&state=attacker-state');
            $this->fail('Expected state validation to fail.');
        } catch (SsoException $exception) {
            $this->assertStringContainsString('state mismatch', $exception->getMessage());
        }

        Http::assertNothingSent();
        $this->assertSame('bound-verifier', session('sso.transactions.bound-state.verifier'));
    }

    public function test_an_authorization_error_must_have_valid_state_and_consumes_the_transaction(): void
    {
        Http::fake();

        try {
            $this->withoutExceptionHandling()
                ->withSession($this->boundSession())
                ->get('/auth/callback?'.http_build_query([
                    'error' => "access_denied\r\nInjected: secret",
                    'state' => 'bound-state',
                ]));
            $this->fail('Expected the authorization error to fail the callback.');
        } catch (SsoException $exception) {
            $this->assertSame('SSO sign-in failed at the identity provider. Please try again.', $exception->getMessage());
        }

        Http::assertNothingSent();
        $this->assertNull(session('sso.transactions.bound-state'));
    }

    public function test_an_authorization_error_cannot_bypass_state_validation(): void
    {
        Http::fake();

        try {
            $this->withoutExceptionHandling()
                ->withSession($this->boundSession())
                ->get('/auth/callback?error=access_denied&state=attacker-state');
            $this->fail('Expected state validation to fail.');
        } catch (SsoException $exception) {
            $this->assertStringContainsString('state mismatch', $exception->getMessage());
        }

        Http::assertNothingSent();
    }

    public function test_authorization_error_codes_are_safely_mapped_without_echoing_provider_details(): void
    {
        $cases = [
            'access_denied' => 'SSO authorization was denied by the identity provider.',
            'login_required' => 'Your identity provider session expired. Please sign in again.',
            'interaction_required' => 'The identity provider requires additional interaction. Please try signing in again.',
            'temporarily_unavailable' => 'The identity provider is temporarily unavailable. Please try again.',
            'invalid_request' => 'The identity provider rejected the sign-in request. Please contact support if this continues.',
            'private_provider_error' => 'SSO sign-in failed at the identity provider. Please try again.',
        ];

        foreach ($cases as $error => $message) {
            try {
                $this->withoutExceptionHandling()
                    ->withSession($this->boundSession())
                    ->get('/auth/callback?'.http_build_query([
                        'error' => $error,
                        'error_description' => 'secret-must-not-leak',
                        'state' => 'bound-state',
                    ]));
                $this->fail('Expected authorization error.');
            } catch (SsoException $exception) {
                $this->assertSame($message, $exception->getMessage());
                $this->assertStringNotContainsString('secret-must-not-leak', $exception->getMessage());
            }
        }

        Http::assertNothingSent();
    }

    public function test_array_pollution_in_state_or_code_fails_without_contacting_the_token_endpoint(): void
    {
        foreach ([
            '/auth/callback?state[]=bound-state&code=authorization-code',
            '/auth/callback?state=bound-state&code[]=authorization-code',
        ] as $callback) {
            Http::fake();

            try {
                $this->withoutExceptionHandling()
                    ->withSession($this->boundSession())
                    ->get($callback);
                $this->fail('Expected malformed callback parameters to fail.');
            } catch (SsoException) {
                $this->addToAssertionCount(1);
            }

            Http::assertNothingSent();
        }
    }

    public function test_it_rejects_a_missing_id_token_before_provisioning_or_login(): void
    {
        $this->fakeOidc($this->jwt->token([
            'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
        ]));

        $this->expectCallbackFailure('no id_token');
    }

    public function test_it_rejects_a_malformed_access_token_response_before_verification(): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
            'https://id.example.test/api/sso/token' => Http::response(['access_token' => ['polluted']]),
        ]);

        $this->expectCallbackFailure('no access_token');
    }

    public function test_an_oauth_only_consumer_does_not_require_an_id_token(): void
    {
        $this->app['config']->set('sso.scopes', 'profile email');
        $accessToken = $this->jwt->token([
            'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
        ]);
        $this->fakeOidc($accessToken);

        $response = $this->withSession($this->boundSession())
            ->get('/auth/callback?code=authorization-code&state=bound-state');

        $response->assertRedirect('/protected?tab=security');
        $this->assertSame('user-1', $this->provisioner->claims['sub']);
    }

    public function test_it_rejects_an_id_token_with_the_wrong_nonce(): void
    {
        $this->fakeOidc(
            $this->jwt->token(['organization_context_id' => self::ORGANIZATION_CONTEXT_ID]),
            $this->jwt->idToken(['nonce' => 'attacker-nonce']),
        );

        $this->expectCallbackFailure('nonce mismatch');
    }

    public function test_it_rejects_access_and_id_tokens_for_different_subjects(): void
    {
        $this->fakeOidc(
            $this->jwt->token(['organization_context_id' => self::ORGANIZATION_CONTEXT_ID]),
            $this->jwt->idToken(['sub' => 'user-2', 'nonce' => 'bound-nonce']),
        );

        $this->expectCallbackFailure('subjects do not match');
    }

    public function test_it_rejects_a_token_for_a_different_organization_than_the_selected_context(): void
    {
        $this->fakeOidc(
            $this->jwt->token(['organization_context_id' => '3efb1df0-1814-480c-9566-42d339758da8']),
            $this->jwt->idToken(['nonce' => 'bound-nonce']),
        );

        $this->expectCallbackFailure('organization context does not match');
    }

    /** @return array<string, string> */
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

final class RecordingProvisioner implements ProvisionsUsers
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
