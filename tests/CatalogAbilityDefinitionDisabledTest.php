<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Support\Facades\Gate;
use Orchestra\Testbench\TestCase;

/**
 * `sso.authz.define_abilities=false` — consumer nào tự định nghĩa hết danh mục
 * thì tắt được phần nạp của package, để hai backend phân quyền không dẫm chân
 * nhau. Cùng lý do với `sso.permissions.gate_enabled`.
 */
final class CatalogAbilityDefinitionDisabledTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('sso.authz.define_abilities', false);
        $app['config']->set('authz.permissions', [['slug' => 'dashboard.view']]);
    }

    public function test_the_package_defines_nothing_when_switched_off(): void
    {
        $this->assertFalse(Gate::has('dashboard.view'));
    }
}
