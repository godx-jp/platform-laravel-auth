<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class GateDelegationDisabledTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('sso.permissions.gate_enabled', false);
        $app['config']->set('authz.permissions', [['slug' => 'dashboard.view']]);
    }

    public function test_a_consumer_owned_resolver_can_answer_catalog_abilities(): void
    {
        Gate::define('dashboard.view', fn (): bool => true);
        Http::fake();

        $user = new GenericUser(['password' => '', 
            'id' => 'user-1',
            'console_access_token' => 'platform-access-token',
            'console_organization_id' => 'org-1',
        ]);

        $this->assertTrue(Gate::forUser($user)->allows('dashboard.view'));
        Http::assertNothingSent();
    }
}
