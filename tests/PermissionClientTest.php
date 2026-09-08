<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\PermissionClient;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class PermissionClientTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.permissions_ttl', 300);
        $app['config']->set('cache.default', 'array');
    }

    protected function setUp(): void
    {
        parent::setUp();
        Cache::clear();
    }

    public function test_it_sends_the_downstream_bearer_and_exact_authorization_context(): void
    {
        Http::fake([
            'https://id.example.test/api/sso/me/permissions*' => Http::response([
                'permissions' => ['records.read', 'records.write'],
                'roles' => ['operator'],
                'service_access' => ['consumer-a' => ['permissions' => ['records.read']]],
                'contract_version' => '1.0',
                'authoritative' => true,
            ]),
        ]);

        $result = $this->app->make(PermissionClient::class)->fetch(
            'service-access-token',
            '9f79d9ee-d735-4673-a80d-c11339f252be',
            '00e9289b-f980-48ea-8943-b91cb4de3e85',
        );

        $this->assertSame(['records.read', 'records.write'], $result['permissions']);
        $this->assertSame(['operator'], $result['roles']);
        $this->assertSame(['consumer-a' => ['permissions' => ['records.read']]], $result['service_access']);
        $this->assertSame('1.0', $result['contract_version']);
        Http::assertSent(fn (Request $request): bool => $request->hasHeader('Authorization', 'Bearer service-access-token')
            && $request['organization_id'] === '9f79d9ee-d735-4673-a80d-c11339f252be'
            && $request['branch_id'] === '00e9289b-f980-48ea-8943-b91cb4de3e85');
    }

    public function test_cache_is_isolated_by_token_organization_and_branch(): void
    {
        Http::fakeSequence()
            ->push(['permissions' => ['a'], 'roles' => [], 'authoritative' => true])
            ->push(['permissions' => ['b'], 'roles' => [], 'authoritative' => true])
            ->push(['permissions' => ['c'], 'roles' => [], 'authoritative' => true]);

        $client = $this->app->make(PermissionClient::class);

        $this->assertSame(['a'], $client->fetch('token-a', 'org-a', 'branch-a')['permissions']);
        $this->assertSame(['a'], $client->fetch('token-a', 'org-a', 'branch-a')['permissions']);
        $this->assertSame(['b'], $client->fetch('token-a', 'org-a', 'branch-b')['permissions']);
        $this->assertSame(['c'], $client->fetch('token-b', 'org-a', 'branch-a')['permissions']);
        Http::assertSentCount(3);
    }

    public function test_platform_denial_fails_closed_without_caching_a_permission_result(): void
    {
        Http::fake([
            '*' => Http::response(['error' => 'CONTEXT_UNAVAILABLE'], 403),
        ]);

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('Permission fetch failed (403)');

        $this->app->make(PermissionClient::class)->fetch('token', 'wrong-org');
    }

    public function test_live_checks_ignore_cached_permissions_and_observe_revocation_on_the_next_call(): void
    {
        Http::fakeSequence()
            ->push(['permissions' => ['records.write'], 'roles' => [], 'authoritative' => true])
            ->push(['permissions' => ['records.read'], 'roles' => [], 'authoritative' => true])
            ->push(['permissions' => [], 'roles' => [], 'authoritative' => true]);

        $client = $this->app->make(PermissionClient::class);
        $this->assertSame(['records.write'], $client->fetch('live-token', 'org-a')['permissions']);
        $this->assertSame(['records.read'], $client->fetchFresh('live-token', 'org-a')['permissions']);
        $this->assertSame([], $client->fetchFresh('live-token', 'org-a')['permissions']);
        Http::assertSentCount(3);
    }

    public function test_live_permission_resolution_never_falls_back_to_a_cached_allow_during_an_outage(): void
    {
        Http::fakeSequence()
            ->push(['permissions' => ['records.write'], 'roles' => [], 'authoritative' => true])
            ->push(['error' => 'unavailable'], 503);

        $client = $this->app->make(PermissionClient::class);
        $client->fetch('live-token', 'org-a');
        $decision = $client->resolveFor('live-token', 'org-a', fresh: true);

        $this->assertFalse($decision['authoritative']);
        $this->assertTrue($decision['permissions']->isEmpty());
        Http::assertSentCount(2);
    }

    public function test_live_permission_resolution_keeps_each_request_token_and_context_separate(): void
    {
        Http::fake(fn (Request $request) => Http::response([
            'permissions' => [$request['organization_id'].'.read'],
            'roles' => [],
            'authoritative' => true,
        ]));
        $client = $this->app->make(PermissionClient::class);

        $this->assertSame(['org-a.read'], $client->fetchFresh('token-a', 'org-a', 'branch-a')['permissions']);
        $this->assertSame(['org-b.read'], $client->fetchFresh('token-b', 'org-b', 'branch-b')['permissions']);
        $this->assertSame(['org-a.read'], $client->fetchFresh('token-a', 'org-a', 'branch-a')['permissions']);
        Http::assertSent(fn (Request $request): bool => $request->hasHeader('Authorization', 'Bearer token-b')
            && $request['organization_id'] === 'org-b' && $request['branch_id'] === 'branch-b');
        Http::assertSentCount(3);
    }

    public function test_permission_redirect_is_not_an_authorization_decision(): void
    {
        Http::fake(['*' => Http::response([
            'permissions' => ['records.write'], 'roles' => [], 'authoritative' => true,
        ], 302, ['Location' => 'https://untrusted.example/'])]);

        $decision = $this->app->make(PermissionClient::class)->resolveFor('token', 'org-a', fresh: true);
        $this->assertFalse($decision['authoritative']);
        $this->assertTrue($decision['permissions']->isEmpty());
        Http::assertSentCount(1);
    }
}
