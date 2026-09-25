<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Contracts\ValidatesDevelopmentSubjects;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * The `sso.auth` middleware exposes two dev/test escape hatches — an already
 * authenticated (actingAs) user, and a `Bearer dev:<subject>` token — that MUST
 * be inert in production, where only a real JWKS-verified bearer is accepted.
 */
final class AuthenticateSsoBypassTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('sso.issuer', 'https://platform.example');
        $app['config']->set('sso.service_slug', 'kintai');
        $app['config']->set('sso.routes.enabled', false);
        $app['config']->set('sso.dev_bypass.enabled', true);
        $app['config']->set('sso.dev_bypass.environments', ['local', 'testing']);

        $app->instance(ProvisionsUsers::class, new BypassProvisioner);
        $app->instance(ValidatesDevelopmentSubjects::class, new AllowPerson42);
    }

    protected function defineRoutes($router): void
    {
        $router->middleware('sso.auth')->get('/protected', function () {
            return response()->json(['id' => optional(auth()->user())->getAuthIdentifier()]);
        });
    }

    public function test_it_passes_through_an_acting_as_user_in_non_production(): void
    {
        $user = new GenericUser(['password' => '', 'id' => 1, 'name' => 'Local Tester']);

        $this->actingAs($user)
            ->getJson('/protected')
            ->assertOk()
            ->assertJson(['id' => 1]);
    }

    public function test_it_provisions_a_dev_subject_bearer_in_non_production(): void
    {
        $this->getJson('/protected', ['Authorization' => 'Bearer dev:person-42'])
            ->assertOk()
            ->assertJson(['id' => BypassProvisioner::PROVISIONED_ID]);
    }

    public function test_acting_as_user_is_rejected_in_production(): void
    {
        Http::fake(['*' => Http::response('', 500)]);
        $this->app['env'] = 'production';

        $user = new GenericUser(['password' => '', 'id' => 1, 'name' => 'Local Tester']);

        $this->actingAs($user)
            ->getJson('/protected')
            ->assertUnauthorized();
    }

    public function test_dev_subject_bearer_is_rejected_in_production(): void
    {
        Http::fake(['*' => Http::response('', 500)]);
        $this->app['env'] = 'production';

        $this->getJson('/protected', ['Authorization' => 'Bearer dev:person-42'])
            ->assertUnauthorized();
    }

    public function test_all_bypasses_are_disabled_without_explicit_opt_in(): void
    {
        $this->app['config']->set('sso.dev_bypass.enabled', false);
        $user = new GenericUser(['password' => '', 'id' => 1, 'name' => 'Local Tester']);

        $this->actingAs($user)->getJson('/protected')->assertUnauthorized();
        $this->getJson('/protected', ['Authorization' => 'Bearer dev:person-42'])
            ->assertUnauthorized();
    }

    public function test_dev_subject_bearer_is_rejected_in_staging(): void
    {
        $this->app['env'] = 'staging';

        $this->getJson('/protected', ['Authorization' => 'Bearer dev:person-42'])
            ->assertUnauthorized();
    }

    public function test_unapproved_dev_subject_is_rejected_without_provisioning(): void
    {
        $this->getJson('/protected', ['Authorization' => 'Bearer dev:attacker'])
            ->assertUnauthorized();
    }
}

final class AllowPerson42 implements ValidatesDevelopmentSubjects
{
    public function allows(string $subject): bool
    {
        return $subject === 'person-42';
    }
}

/**
 * Minimal JIT provisioner: always takes the provision() path so the dev-bearer
 * hatch is exercised end-to-end.
 */
final class BypassProvisioner implements ProvisionsUsers
{
    public const PROVISIONED_ID = 99;

    public function provision(array $claims, array $tokens): Authenticatable
    {
        return new GenericUser(['password' => '', 'id' => self::PROVISIONED_ID, 'sub' => $claims['sub'] ?? null]);
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        return null;
    }
}
