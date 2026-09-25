<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoConfigurationException;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Support\OrganizationConfigurationGuard;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class OrganizationConfigurationGuardTest extends TestCase
{
    private const ORGANIZATION_CONTEXT_ID = '9f79d9ee-d735-4673-a80d-c11339f252be';

    private const PLATFORM_ORGANIZATION_ID = '019f6ece-2629-730a-ab0b-0f323d4e2e02';

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('session.driver', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.client_secret', 'consumer-a-secret');
        $app['config']->set('sso.redirect_uri', 'https://consumer-a.example.test/auth/callback');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
        ]);
    }

    /**
     * A missing value is NOT a hard error: the callback prefers organization_context_id
     * and falls back to organization_id, so which one a consumer needs depends on the
     * token its IdP issues. Refusing to start SSO here would lock out correctly
     * configured consumers; `sso:doctor` warns instead.
     */
    public function test_it_does_not_block_redirect_when_only_the_console_organization_is_configured(): void
    {
        config()->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);

        $this->get('/auth/redirect')->assertRedirect();
    }

    public function test_it_fails_redirect_when_both_values_are_identical(): void
    {
        config()->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);
        config()->set('sso.organization_id', self::ORGANIZATION_CONTEXT_ID);

        $this->withoutExceptionHandling();
        $this->expectException(SsoConfigurationException::class);
        $this->expectExceptionMessage('identical');

        $this->get('/auth/redirect');
    }

    public function test_it_allows_redirect_when_both_organization_values_are_configured(): void
    {
        config()->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);
        config()->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);

        $this->get('/auth/redirect')->assertRedirect();
    }

    public function test_it_allows_redirect_when_organization_context_is_passed_on_the_query_without_env_pairing(): void
    {
        $this->get('/auth/redirect?'.http_build_query([
            'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
        ]))->assertRedirect();
    }

    public function test_doctor_warns_but_succeeds_when_only_one_value_is_set(): void
    {
        config()->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);

        $this->artisan('sso:doctor')
            ->expectsOutputToContain('SSO_ORGANIZATION_ID is not set')
            ->assertExitCode(0);
    }

    public function test_doctor_fails_when_both_values_are_identical(): void
    {
        config()->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);
        config()->set('sso.organization_id', self::ORGANIZATION_CONTEXT_ID);

        $this->artisan('sso:doctor')
            ->expectsOutputToContain('identical')
            ->assertExitCode(1);
    }

    public function test_doctor_succeeds_when_both_values_are_set_and_differ(): void
    {
        config()->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);
        config()->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);

        $this->artisan('sso:doctor')
            ->expectsOutputToContain('Both organization values are set and differ')
            ->assertSuccessful();
    }
}
