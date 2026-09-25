<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * User-facing SSO failures must never render as raw 500s: a denied consent, an
 * expired state transaction or an unreachable IdP redirects to the configured
 * failure destination with the error flashed under `sso.error`. Only operator
 * misconfiguration (SsoConfigurationException) keeps default 500 handling.
 */
final class SsoFailureRenderingTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('session.driver', 'array');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('app.debug', false);
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.client_secret', 'consumer-a-secret');
        $app['config']->set('sso.redirect_uri', 'https://consumer-a.example.test/auth/callback');
        $app['config']->set('sso.after_login', '/home');
        $app['config']->set('sso.after_logout', '/goodbye');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
        $this->app->instance(ProvisionsUsers::class, new NullProvisioner);
    }

    public function test_a_denied_authorization_redirects_with_a_flashed_error_instead_of_a_500(): void
    {
        Http::fake();

        $response = $this->withSession($this->boundSession())
            ->get('/auth/callback?error=access_denied&state=bound-state');

        $response->assertRedirect('/goodbye');
        $response->assertSessionHas('sso.error', 'SSO authorization was denied by the identity provider.');
        Http::assertNothingSent();
    }

    public function test_an_expired_or_unknown_state_redirects_with_a_flashed_error(): void
    {
        Http::fake();

        $response = $this->get('/auth/callback?code=authorization-code&state=stale-state');

        $response->assertRedirect('/goodbye');
        $response->assertSessionHas('sso.error', 'SSO state mismatch — possible CSRF or expired flow.');
        Http::assertNothingSent();
    }

    public function test_the_failure_redirect_destination_is_configurable(): void
    {
        config()->set('sso.failure_redirect', '/login?sso=failed');
        Http::fake();

        $this->withSession($this->boundSession())
            ->get('/auth/callback?error=access_denied&state=bound-state')
            ->assertRedirect('/login?sso=failed');
    }

    public function test_a_separately_hosted_frontend_can_receive_the_failure_message_in_the_query(): void
    {
        config()->set('sso.failure_redirect', 'https://consumer-a.example.test/login?redirect=%2Fhome');
        config()->set('sso.failure_query_parameter', 'error');
        Http::fake();

        $response = $this->withSession($this->boundSession())
            ->get('/auth/callback?error=access_denied&state=bound-state');

        $response->assertRedirect('https://consumer-a.example.test/login?redirect=%2Fhome&error=SSO%20authorization%20was%20denied%20by%20the%20identity%20provider.');
        $response->assertSessionHas('sso.error', 'SSO authorization was denied by the identity provider.');
    }

    public function test_an_unreachable_idp_redirects_instead_of_crashing(): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response('upstream down', 503),
        ]);

        $response = $this->withSession($this->boundSession())
            ->get('/auth/callback?code=authorization-code&state=bound-state');

        $response->assertRedirect('/goodbye');
        $response->assertSessionHas('sso.error');
    }

    public function test_missing_organization_configuration_is_still_an_operator_500(): void
    {
        config()->set('sso.organization_context_id', '');

        $this->get('/auth/redirect')->assertStatus(500);
    }

    /** @return array<string, mixed> */
    private function boundSession(): array
    {
        return [
            'sso.transactions' => [
                'bound-state' => [
                    'verifier' => 'bound-verifier',
                    'nonce' => 'bound-nonce',
                    'organization_context_id' => '9f79d9ee-d735-4673-a80d-c11339f252be',
                    'return' => '/protected',
                    'created_at' => now()->timestamp,
                ],
            ],
        ];
    }
}

final class NullProvisioner implements ProvisionsUsers
{
    public function provision(array $claims, array $tokens): Authenticatable
    {
        return new GenericUser(['password' => '', 'id' => $claims['sub'] ?? 'user']);
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        return null;
    }
}
