<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class SyncAuthzCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_id', 'consumer-a');
        $app['config']->set('sso.admin_token', 'admin-secret');
        $app['config']->set('sso.authz_mode', 'admin');
        $app['config']->set('sso.http_timeout', 5);
        $app['config']->set('authz', $this->catalog('consumer-a.read'));
    }

    public function test_empty_catalog_is_a_no_op(): void
    {
        Http::fake();
        config()->set('authz', [
            'permissions' => [],
            'roles' => [],
            'default_role' => null,
        ]);

        $this->artisan('dxs:sync-authz')
            ->expectsOutputToContain('nothing to sync')
            ->assertSuccessful();

        Http::assertNothingSent();
    }

    public function test_missing_service_id_fails_before_http(): void
    {
        Http::fake();
        config()->set('sso.service_id', '');

        $this->artisan('dxs:sync-authz')->assertFailed();

        Http::assertNothingSent();
    }

    public function test_dry_run_is_deterministic_and_performs_no_http_request(): void
    {
        Http::fake();

        $this->artisan('dxs:sync-authz', ['--dry-run' => true])
            ->expectsOutputToContain('consumer-a.read')
            ->assertSuccessful();

        Http::assertNothingSent();
    }

    public function test_invalid_duplicates_unknown_references_and_default_role_fail_before_http(): void
    {
        Http::fake();

        foreach ([
            ['permissions' => [['slug' => 'same'], ['slug' => 'same']]],
            ['permissions' => [['slug' => 'known']], 'roles' => [['role' => 'admin', 'permissions' => ['unknown']]]],
            ['permissions' => [['slug' => '']]],
            ['permissions' => [['slug' => 'Invalid Slug']]],
            ['permissions' => [['slug' => 'known']], 'roles' => [], 'default_role' => 'missing'],
        ] as $catalog) {
            config()->set('authz', $catalog);

            $this->artisan('dxs:sync-authz')->assertFailed();
        }

        Http::assertNothingSent();
    }

    public function test_missing_admin_token_fails_before_http(): void
    {
        Http::fake();
        config()->set('sso.authz_mode', 'admin');
        config()->set('sso.admin_token', '');

        $this->artisan('dxs:sync-authz')->assertFailed();

        Http::assertNothingSent();
    }

    public function test_dev_mode_puts_catalog_to_dev_admin_mirror_with_admin_key(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);
        config()->set('sso.authz_mode', 'dev');
        config()->set('sso.admin_key', 'dev-admin-key');
        config()->set('sso.admin_token', '');

        $this->artisan('dxs:sync-authz')->assertSuccessful();

        Http::assertSent(fn (Request $request): bool => $request->method() === 'PUT'
            && $request->url() === 'https://id.example.test/api/dev/services/consumer-a/authz'
            && $request->hasHeader('X-Admin-Key', 'dev-admin-key')
            && ! $request->hasHeader('Authorization')
            && $request->data() === $this->catalog('consumer-a.read'));
    }

    public function test_dev_mode_routes_by_service_slug_not_service_id(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);
        config()->set('sso.authz_mode', 'dev');
        config()->set('sso.admin_key', 'dev-admin-key');
        config()->set('sso.service_id', '01900000-0000-7000-8000-000000000000');
        config()->set('sso.service_slug', 'consumer-a');

        $this->artisan('dxs:sync-authz')->assertSuccessful();

        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://id.example.test/api/dev/services/consumer-a/authz');
    }

    public function test_admin_key_without_explicit_mode_auto_selects_dev(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);
        config()->set('sso.authz_mode', '');
        config()->set('sso.admin_key', 'dev-admin-key');
        config()->set('sso.admin_token', '');

        $this->artisan('dxs:sync-authz')->assertSuccessful();

        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://id.example.test/api/dev/services/consumer-a/authz'
            && $request->hasHeader('X-Admin-Key', 'dev-admin-key'));
    }

    public function test_missing_admin_key_fails_in_dev_mode_before_http(): void
    {
        Http::fake();
        config()->set('sso.authz_mode', 'dev');
        config()->set('sso.admin_key', '');

        $this->artisan('dxs:sync-authz')->assertFailed();

        Http::assertNothingSent();
    }

    public function test_invalid_authz_mode_fails_before_http(): void
    {
        Http::fake();
        config()->set('sso.authz_mode', 'production');

        $this->artisan('dxs:sync-authz')->assertFailed();

        Http::assertNothingSent();
    }

    public function test_dev_dry_run_prints_equivalent_curl_without_http(): void
    {
        Http::fake();
        config()->set('sso.authz_mode', 'dev');
        config()->set('sso.admin_key', 'dev-admin-key');

        $exitCode = Artisan::call('dxs:sync-authz', ['--dry-run' => true]);
        $output = Artisan::output();

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('curl -sS -X PUT', $output);
        // The real key must never reach the terminal or CI logs.
        $this->assertStringNotContainsString('dev-admin-key', $output);
        $this->assertStringContainsString('$SSO_ADMIN_KEY', $output);
        $this->assertStringContainsString('api/dev/services/consumer-a/authz', $output);

        Http::assertNothingSent();
    }

    public function test_default_endpoint_payload_and_repeated_sync_match_the_platform_contract(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);

        $this->artisan('dxs:sync-authz')->assertSuccessful();
        $this->artisan('dxs:sync-authz')->assertSuccessful();

        Http::assertSentCount(2);
        Http::assertSent(fn (Request $request): bool => $request->method() === 'PUT'
            && $request->url() === 'https://id.example.test/api/admin/catalog/consumer-a/authz'
            && $request->hasHeader('Authorization', 'Bearer admin-secret')
            && $request->data() === $this->catalog('consumer-a.read')
            && ! array_key_exists('code', $request['permissions'][0])
            && ! array_key_exists('name', $request['permissions'][0]));
    }

    public function test_service_identifier_is_encoded_and_path_is_configurable(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);
        config()->set('sso.service_id', 'payroll.v2-prod');
        config()->set('sso.authz_path', 'api/dev/services/{service}/authz');

        $this->artisan('dxs:sync-authz')->assertSuccessful();

        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://id.example.test/api/dev/services/payroll.v2-prod/authz');
    }

    public function test_two_services_send_disjoint_catalogs_to_disjoint_endpoints(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);

        config()->set('sso.service_id', 'service-a');
        $this->artisan('dxs:sync-authz')->assertSuccessful();

        config()->set('sso.service_id', 'service-b');
        config()->set('authz', $this->catalog('consumer-b.write'));
        $this->artisan('dxs:sync-authz')->assertSuccessful();

        Http::assertSent(fn (Request $request): bool => str_contains($request->url(), '/service-a/authz')
            && $request['permissions'][0]['slug'] === 'consumer-a.read');
        Http::assertSent(fn (Request $request): bool => str_contains($request->url(), '/service-b/authz')
            && $request['permissions'][0]['slug'] === 'consumer-b.write');
    }

    public function test_missing_optional_catalog_keys_are_sent_with_platform_defaults(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);
        config()->set('authz', [
            'permissions' => [['slug' => 'consumer-a.read', 'display_name' => 'Permission']],
        ]);

        $this->artisan('dxs:sync-authz')->assertSuccessful();

        Http::assertSent(fn (Request $request): bool => $request['roles'] === []
            && $request['default_role'] === null);
    }

    public function test_failed_sync_does_not_reflect_the_response_body(): void
    {
        Http::fake(['*' => Http::response(['debug' => 'access-token-secret'], 422)]);

        try {
            $this->artisan('dxs:sync-authz')->run();
            $this->fail('Expected sync failure.');
        } catch (SsoException $exception) {
            $this->assertSame('Permission catalog sync failed.', $exception->getMessage());
            $this->assertStringNotContainsString('access-token-secret', $exception->getMessage());
        }
    }

    public function test_published_permission_config_has_a_valid_empty_shape(): void
    {
        $catalog = require dirname(__DIR__).'/config/authz.php';

        $this->assertSame([
            'permissions' => [],
            'roles' => [],
            'default_role' => null,
        ], $catalog);
    }

    /** @return array{permissions: array<int, array{slug: string, display_name: string}>, roles: array<int, array{role: string, permissions: array<int, string>}>, default_role: string} */
    private function catalog(string $slug): array
    {
        return [
            'permissions' => [['slug' => $slug, 'display_name' => 'Permission']],
            'roles' => [['role' => 'operator', 'permissions' => [$slug]]],
            'default_role' => 'operator',
        ];
    }
}
