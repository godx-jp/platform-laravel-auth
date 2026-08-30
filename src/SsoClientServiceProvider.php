<?php

declare(strict_types=1);

namespace Dxs\Auth;

use Dxs\Auth\Authorization\LocalAbilityResolver;
use Dxs\Auth\Authorization\PermissionCatalog;
use Dxs\Auth\Console\InstallCommand;
use Dxs\Auth\Console\SeedAuthzCommand;
use Dxs\Auth\Console\SyncAuthzCommand;
use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Contracts\ValidatesDevelopmentSubjects;
use Dxs\Auth\Http\Middleware\AuthenticateSso;
use Dxs\Auth\Http\Middleware\AuthorizeSsoPermission;
use Dxs\Auth\Provisioning\DatabaseUserProvisioner;
use Dxs\Auth\Services\JwtVerifier;
use Dxs\Auth\Services\LogoutSessionRegistry;
use Dxs\Auth\Services\OidcDiscovery;
use Dxs\Auth\Services\PermissionClient;
use Dxs\Auth\Services\PlatformContextClient;
use Dxs\Auth\Services\TokenExchanger;
use Dxs\Auth\Services\TokenRefresher;
use Dxs\Auth\Support\ConfigDevelopmentSubjectValidator;
use Dxs\Auth\Sync\AuthzResources;
use Godx\Sync\Registry\SyncRegistry;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

final class SsoClientServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/sso.php', 'sso');
        $this->mergeConfigFrom(__DIR__.'/../config/authz.php', 'authz');

        $this->app->singletonIf(ProvisionsUsers::class, DatabaseUserProvisioner::class);
        $this->app->singletonIf(ValidatesDevelopmentSubjects::class, ConfigDevelopmentSubjectValidator::class);
        $this->app->singleton(OidcDiscovery::class);
        $this->app->singleton(JwtVerifier::class);
        $this->app->singleton(LogoutSessionRegistry::class);
        $this->app->singleton(TokenExchanger::class);
        $this->app->singleton(TokenRefresher::class);
        $this->app->singleton(PermissionClient::class);
        $this->app->singleton(PlatformContextClient::class);
        $this->app->singleton(LocalAbilityResolver::class);
        $this->app->singleton(SsoManager::class);
    }

    public function boot(Router $router): void
    {
        // Từ vựng authz khai vào đường ống đồng bộ chung. Khai ở `boot` chứ
        // không `register`: registry của package sync là singleton dựng trong
        // `register` của nó, và thứ tự nạp provider giữa hai package không được
        // phép quyết định loại nào tồn tại.
        AuthzResources::register($this->app->make(SyncRegistry::class));

        $this->publishes([
            __DIR__.'/../config/sso.php' => config_path('sso.php'),
            __DIR__.'/../config/authz.php' => config_path('authz.php'),
        ], 'sso-config');

        $this->publishes([
            __DIR__.'/../database/migrations/add_sso_identity_columns_to_users_table.php.stub' => database_path('migrations/'.date('Y_m_d_His').'_add_sso_identity_columns_to_users_table.php'),
        ], 'sso-migrations');

        // Schema Omnify của các bảng do package định nghĩa. Consumer publish
        // một lần rồi sở hữu bản copy — thêm cột riêng thoải mái. Cố ý KHÔNG
        // đọc thẳng từ vendor: schema phải là file dự án tự quản, và cách này
        // tránh phải dùng `kind: extend` (omnify bỏ qua property khai trên stub
        // extend, nên cột thêm vào sẽ lặng lẽ không bao giờ được sinh ra).
        $this->publishes([
            __DIR__.'/../schemas' => (string) config('sso.schemas_path', base_path('schemas/Sso')),
        ], 'sso-schemas');

        $this->publishes([
            __DIR__.'/../stubs/authz.php.stub' => config_path('authz.php'),
        ], 'sso-authz');

        $this->publishes([
            __DIR__.'/../stubs/UserProvisioner.php.stub' => app_path('Sso/UserProvisioner.php'),
        ], 'sso-provisioner');

        if ($this->app->runningInConsole()) {
            $this->commands([SyncAuthzCommand::class, SeedAuthzCommand::class, InstallCommand::class]);
        }

        // Opt-in scheduled catalog sync: `sso.sync.authz.auto` puts
        // `dxs:sync-authz --if-changed` on the scheduler at the configured
        // frequency (a preset like `daily`/`hourly`, or a cron expression),
        // so the platform converges on config/authz.php without manual runs.
        $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
            if (! (bool) config('sso.sync.authz.auto')) {
                return;
            }

            $event = $schedule->command('dxs:sync-authz --if-changed');
            $frequency = (string) config('sso.sync.authz.schedule', 'daily');

            if (str_contains($frequency, ' ')) {
                $event->cron($frequency);
            } elseif (method_exists($event, $frequency)) {
                $event->{$frequency}();
            } else {
                $event->daily();
            }
        });

        // `sso.auth` — validate a platform-issued bearer JWT (JWKS/aud/exp) and
        // resolve the local user. Replaces the gateway header-trust middleware.
        $router->aliasMiddleware('sso.auth', AuthenticateSso::class);

        // `sso.can:{ability,…}` — authenticate the bearer AND require every
        // listed platform ability in one alias, with RFC 6750
        // `insufficient_scope` semantics on denial.
        $router->aliasMiddleware('sso.can', AuthorizeSsoPermission::class);

        // Package tự nạp danh mục vào Gate (1.0.0). Trước đây consumer phải tự
        // `Gate::define` cho từng slug, và khi họ quên thì `Gate::before` là
        // câu trả lời DUY NHẤT — nên "không phân giải được" chỉ có thể là
        // `false`. Có định nghĩa ở đây thì null mới có chỗ để rơi xuống.
        //
        // Định nghĩa của package đọc BẢNG CỤC BỘ, tức đúng thứ
        // `dxs:seed-authz` ghi. Consumer định nghĩa lại slug nào thì thắng slug
        // đó: provider của app boot SAU package, và `Gate::define` sau đè trước.
        if ((bool) config('sso.authz.define_abilities', true)) {
            foreach (PermissionCatalog::slugs() as $slug) {
                Gate::define($slug, fn (Authenticatable $user): bool => $this->app
                    ->make(LocalAbilityResolver::class)
                    ->allows($user, $slug));
            }
        }

        // Authorization DECISIONS stay on the platform: a granted ability is one
        // present in the user's platform-resolved permission list. Explicit
        // policies still run for abilities not in the list (Gate::before → null).
        if ((bool) config('sso.permissions.gate_enabled', true)) {
            Gate::before(function (Authenticatable $user, string $ability): ?bool {
                if (! in_array($ability, PermissionCatalog::slugs(), true)) {
                    return null;
                }

                $token = data_get($user, 'console_access_token');
                $org = data_get($user, 'console_organization_id');

                // KHÔNG có ngữ cảnh Platform ⇒ không phân giải được ⇒ `null`,
                // KHÔNG phải `false` (thay đổi phá vỡ của 1.0.0).
                //
                // `false` ở đây đoản mạch toàn bộ Gate: mọi `Gate::define` và
                // mọi Policy của app bị bỏ qua, nên một request không mang
                // `console_access_token` bị từ chối mọi ability trong danh mục,
                // kể cả của org-admin, và không một dòng log. Một câu "tôi
                // không biết" không được phép trở thành câu "không".
                if (! is_string($token) || $token === '' || ! is_string($org) || $org === '') {
                    return null;
                }

                $this->app->make(TokenRefresher::class)->ensureFresh($user);
                $token = data_get($user, 'console_access_token');
                if (! is_string($token) || $token === '') {
                    return null;
                }

                $branch = data_get($user, 'console_branch_id');
                $branch = is_string($branch) && $branch !== '' ? $branch : null;

                $decision = $this->app->make(PermissionClient::class)
                    ->resolveFor($token, $org, $branch);

                // Từ đây trở xuống Platform ĐÃ trả lời, nên `false` là câu trả
                // lời của nó chứ không phải sự im lặng của ta:
                //
                // - `authoritative === false` là read model đang suy giảm
                //   (PermissionClient fail-closed khi Platform không với tới).
                //   Trả null ở đây sẽ để một sự cố mạng âm thầm MỞ mọi ability
                //   có một policy cục bộ dễ tính — đúng thứ fail-closed sinh ra
                //   để chặn.
                // - authoritative mà slug không có trong danh sách nghĩa là
                //   Platform nói KHÔNG. Nguồn sự thật đã phát biểu; một policy
                //   cục bộ không được phép lật nó.
                return $decision['authoritative'] && $decision['permissions']->contains($ability);
            });
        }

        // Guests bounced by Laravel's `auth` middleware land on route('login');
        // register the SSO fallback unless the app defines its own.
        if (config('sso.routes.enabled') && config('sso.routes.login_redirect', true)) {
            $this->app->booted(function () use ($router): void {
                if (! $router->getRoutes()->hasNamedRoute('login')) {
                    $router->get('/login', function (Request $request) {
                        $returnPath = $request->query('return');

                        return redirect()->route('sso.redirect', is_string($returnPath)
                            ? ['return' => $returnPath]
                            : []);
                    })
                        ->middleware('web')
                        ->name('login');
                }
            });
        }

        if (config('sso.routes.enabled')) {
            $router->group([
                'prefix' => config('sso.routes.prefix'),
                'middleware' => config('sso.routes.middleware'),
            ], fn () => $this->loadRoutesFrom(__DIR__.'/../routes/web.php'));
        }
    }
}
