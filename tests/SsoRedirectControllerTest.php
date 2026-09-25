<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class SsoRedirectControllerTest extends TestCase
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

    public function test_it_binds_the_platform_selected_organization_to_the_oauth_transaction(): void
    {
        $response = $this->get('/auth/redirect?'.http_build_query([
            'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
            'return' => '/protected',
        ]));

        $response->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

        $this->assertSame(self::ORGANIZATION_CONTEXT_ID, $query['organization_context_id']);
        $this->assertSame('consumer-a', $query['service_slug']);
        $this->assertSame('code', $query['response_type']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertNotSame('', $query['state']);
        $this->assertNotSame('', $query['nonce']);
        $this->assertNotSame('', $query['code_challenge']);
        $response->assertSessionHas("sso.transactions.{$query['state']}.organization_context_id", self::ORGANIZATION_CONTEXT_ID);
        $response->assertSessionHas("sso.transactions.{$query['state']}.return", '/protected');
    }

    public function test_fixed_single_tenant_context_cannot_be_overridden_by_the_request(): void
    {
        $this->app['config']->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);
        $this->app['config']->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);

        $response = $this->get('/auth/redirect?organization_context_id=3efb1df0-1814-480c-9566-42d339758da8');
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

        $this->assertSame(self::ORGANIZATION_CONTEXT_ID, $query['organization_context_id']);
    }

    public function test_an_authenticated_multi_tenant_consumer_can_reauthorize_for_a_selected_organization(): void
    {
        $selectedOrganization = '3efb1df0-1814-480c-9566-42d339758da8';
        $this->app['config']->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);
        $this->app['config']->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);
        $this->app['config']->set('sso.allow_organization_switching', true);
        $this->app['auth']->setUser(new GenericUser(['id' => 1]));

        $response = $this->get('/auth/redirect?'.http_build_query([
            'organization_context_id' => $selectedOrganization,
            'return' => '/dashboard',
        ]));
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

        $this->assertSame($selectedOrganization, $query['organization_context_id']);
        $response->assertSessionHas("sso.transactions.{$query['state']}.organization_context_id", $selectedOrganization);
        $response->assertSessionHas("sso.transactions.{$query['state']}.return", '/dashboard');
    }

    public function test_an_unauthenticated_request_cannot_override_a_fixed_context_even_when_switching_is_enabled(): void
    {
        $this->app['config']->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);
        $this->app['config']->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);
        $this->app['config']->set('sso.allow_organization_switching', true);

        $response = $this->get('/auth/redirect?organization_context_id=3efb1df0-1814-480c-9566-42d339758da8');
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

        $this->assertSame(self::ORGANIZATION_CONTEXT_ID, $query['organization_context_id']);
    }

    public function test_a_malformed_authenticated_switch_context_never_falls_back_to_the_fixed_tenant(): void
    {
        $this->app['config']->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);
        $this->app['config']->set('sso.organization_id', self::PLATFORM_ORGANIZATION_ID);
        $this->app['config']->set('sso.allow_organization_switching', true);
        $this->app['auth']->setUser(new GenericUser(['id' => 1]));
        $this->withoutExceptionHandling();

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('A valid organization context is required');

        $this->get('/auth/redirect?organization_context_id=not-a-uuid');
    }

    #[DataProvider('invalidOrganizationContexts')]
    public function test_missing_or_malformed_organization_context_fails_before_authorization(string $query): void
    {
        $this->withoutExceptionHandling();

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('A valid organization context is required');

        $this->get('/auth/redirect'.$query);
    }

    /** @return array<string, array{string}> */
    public static function invalidOrganizationContexts(): array
    {
        return [
            'missing' => [''],
            'malformed' => ['?organization_context_id=not-a-uuid'],
            'array pollution' => ['?organization_context_id[]=9f79d9ee-d735-4673-a80d-c11339f252be'],
        ];
    }

    #[DataProvider('unsafeReturnPaths')]
    public function test_it_never_persists_an_unsafe_user_supplied_return_destination(string $returnPath): void
    {
        $response = $this->get('/auth/redirect?'.http_build_query([
            'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
            'return' => $returnPath,
        ]));

        $response->assertRedirect();
        $response->assertSessionMissing('sso.return');
    }

    /** @return array<string, array{string}> */
    public static function unsafeReturnPaths(): array
    {
        return [
            'absolute HTTPS URL' => ['https://attacker.example/steal'],
            'protocol-relative URL' => ['//attacker.example/steal'],
            'backslash authority confusion' => ['/\\attacker.example/steal'],
            'encoded protocol-relative URL' => ['/%2Fattacker.example/steal'],
            'double encoded protocol-relative URL' => ['/%252Fattacker.example/steal'],
            'encoded backslash authority confusion' => ['/%5Cattacker.example/steal'],
            'CRLF header injection' => ["/safe\r\nLocation: https://attacker.example"],
            'non-path value' => ['dashboard'],
        ];
    }
}
