<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Provisioning\DatabaseUserProvisioner;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Auth\User as AuthUser;
use Illuminate\Support\Carbon;
use Orchestra\Testbench\TestCase;

/**
 * The turnkey story: `composer require` + `sso:install` + `migrate` is a
 * working downstream. The package ships the users-table identity migration,
 * a zero-config DatabaseUserProvisioner bound as the default, publishable
 * stubs for customisation, and a fallback named `login` route.
 */
final class TurnkeyInstallTest extends TestCase
{
    /** @var list<string> */
    private array $published = [];

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('session.driver', 'array');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('database.default', 'testing');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.provisioner.model', TurnkeyUser::class);
    }

    protected function tearDown(): void
    {
        foreach ($this->published as $path) {
            @unlink($path);
        }
        parent::tearDown();
    }

    // ---- default provisioner ---------------------------------------------

    public function test_the_database_provisioner_is_the_default_binding(): void
    {
        $this->assertInstanceOf(DatabaseUserProvisioner::class, $this->app->make(ProvisionsUsers::class));
    }

    public function test_a_consumer_binding_still_wins_over_the_default(): void
    {
        $custom = new class implements ProvisionsUsers
        {
            public function provision(array $claims, array $tokens): Authenticatable
            {
                return new GenericUser(['password' => '', 'id' => 'custom']);
            }

            public function resolveBySubject(string $subject): ?Authenticatable
            {
                return null;
            }
        };
        $this->app->singleton(ProvisionsUsers::class, fn () => $custom);

        $this->assertSame($custom, $this->app->make(ProvisionsUsers::class));
    }

    public function test_the_published_migration_plus_default_provisioner_jit_provisions_a_full_user(): void
    {
        $this->migrateUsersTable();

        $user = $this->app->make(ProvisionsUsers::class)->provision([
            'sub' => 'cu_1',
            'name' => 'Turnkey User',
            'email' => 'turnkey@example.test',
            'organization_id' => 'org-1',
            'organization_context_id' => 'console-org-1',
        ], [
            'access_token' => 'at-1',
            'refresh_token' => 'rt-1',
            'expires_in' => 900,
        ]);

        $this->assertSame('cu_1', $user->console_user_id);
        $this->assertSame('Turnkey User', $user->name);
        $this->assertSame('turnkey@example.test', $user->email);
        $this->assertSame('console-org-1', $user->console_organization_id);
        $this->assertSame('at-1', $user->console_access_token);
        $this->assertSame('rt-1', $user->console_refresh_token);
        $this->assertEqualsWithDelta(Carbon::now()->addSeconds(900)->timestamp, Carbon::parse($user->console_token_expires_at)->timestamp, 5);
        $this->assertNull($user->password);
    }

    public function test_relogin_updates_the_same_row_and_resolve_by_subject_finds_it(): void
    {
        $this->migrateUsersTable();
        $provisioner = $this->app->make(ProvisionsUsers::class);

        $provisioner->provision(['sub' => 'cu_1', 'name' => 'Old', 'email' => 'old@example.test'], ['access_token' => 'at-1']);
        $provisioner->provision(['sub' => 'cu_1', 'name' => 'New', 'email' => 'new@example.test'], ['access_token' => 'at-2']);

        $this->assertSame(1, TurnkeyUser::query()->count());

        $resolved = $provisioner->resolveBySubject('cu_1');
        $this->assertSame('New', $resolved->name);
        $this->assertSame('at-2', $resolved->console_access_token);

        $this->assertNull($provisioner->resolveBySubject('cu_unknown'));
    }

    // ---- sso:install ------------------------------------------------------

    public function test_sso_install_publishes_config_migration_and_authz_catalog(): void
    {
        $this->artisan('sso:install')->assertExitCode(0);

        $this->published = array_merge(
            [config_path('sso.php'), config_path('authz.php')],
            glob(database_path('migrations/*_add_sso_identity_columns_to_users_table.php')) ?: [],
        );

        $this->assertFileExists(config_path('sso.php'));
        $this->assertFileExists(config_path('authz.php'));
        $this->assertNotEmpty(glob(database_path('migrations/*_add_sso_identity_columns_to_users_table.php')));
    }

    public function test_sso_install_can_also_publish_the_provisioner_stub(): void
    {
        $this->artisan('sso:install --provisioner')->assertExitCode(0);

        $this->published = array_merge(
            [config_path('sso.php'), config_path('authz.php'), app_path('Sso/UserProvisioner.php')],
            glob(database_path('migrations/*_add_sso_identity_columns_to_users_table.php')) ?: [],
        );

        $this->assertFileExists(app_path('Sso/UserProvisioner.php'));
        $this->assertStringContainsString('implements ProvisionsUsers', (string) file_get_contents(app_path('Sso/UserProvisioner.php')));
    }

    // ---- login fallback route ---------------------------------------------

    public function test_a_named_login_route_falls_back_into_the_sso_redirect(): void
    {
        $this->get('/login')->assertRedirect(route('sso.redirect'));
        $this->get('/login?return=%2F')->assertRedirect(route('sso.redirect', ['return' => '/']));
        $this->get('/login?return=https%3A%2F%2Fevil.example')
            ->assertRedirect(route('sso.redirect', ['return' => 'https://evil.example']));
        $this->assertTrue($this->app['router']->getRoutes()->hasNamedRoute('login'));
    }

    // ---- helpers ----------------------------------------------------------

    private function migrateUsersTable(): void
    {
        $this->loadLaravelMigrations();

        $migration = require __DIR__.'/../database/migrations/add_sso_identity_columns_to_users_table.php.stub';
        $migration->up();
    }
}

final class TurnkeyUser extends AuthUser
{
    protected $table = 'users';

    protected $guarded = ['console_user_id', 'console_organization_id', 'console_access_token', 'console_refresh_token', 'console_token_expires_at'];
}
