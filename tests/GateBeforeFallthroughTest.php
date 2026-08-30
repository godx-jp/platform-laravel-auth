<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * Thay đổi phá vỡ số 1 của 1.0.0: `Gate::before` trả `null` khi KHÔNG PHÂN GIẢI
 * ĐƯỢC, thay vì `false`.
 *
 * Ranh giới đo ở đây, và nó hẹp hơn tiêu đề nghe có vẻ:
 *
 * | tình huống | trước | sau | vì sao |
 * |---|---|---|---|
 * | thiếu `console_access_token` / `console_organization_id` | false | **null** | ta không biết, và "không biết" ≠ "không" |
 * | Platform trả lời, slug KHÔNG trong danh sách | false | false | Platform nói không |
 * | read model không authoritative | false | false | fail-closed: sự cố mạng không được phép MỞ quyền |
 *
 * Hai dòng cuối cố ý không đổi. Xem thêm hai bài trong {@see GateDelegationTest}
 * canh đúng chúng.
 */
final class GateBeforeFallthroughTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.permissions_path', 'api/sso/me/permissions');
        // Bài này đo RIÊNG `Gate::before`, nên tắt phần định nghĩa của package
        // để câu trả lời rơi đúng vào định nghĩa mà bài tự đặt.
        $app['config']->set('sso.authz.define_abilities', false);
        $app['config']->set('authz.permissions', [
            ['slug' => 'dashboard.view'],
            ['slug' => 'employees.delete'],
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
    }

    public function test_a_user_without_platform_context_falls_through_to_a_local_policy(): void
    {
        Http::fake();
        Gate::define('dashboard.view', fn (): bool => true);

        // Trước 1.0.0 bài này FALSE: Gate::before đoản mạch thành deny và định
        // nghĩa ngay trên không bao giờ chạy.
        $this->assertTrue(Gate::forUser(new GenericUser(['id' => 'local-1']))->allows('dashboard.view'));
        Http::assertNothingSent();
    }

    public function test_falling_through_still_denies_when_the_app_defines_nothing(): void
    {
        Http::fake();

        $this->assertFalse(Gate::forUser(new GenericUser(['id' => 'local-1']))->allows('dashboard.view'));
        Http::assertNothingSent();
    }

    public function test_a_local_policy_may_also_deny_a_catalog_ability(): void
    {
        Http::fake();
        Gate::define('dashboard.view', fn (): bool => false);

        $this->assertFalse(Gate::forUser(new GenericUser(['id' => 'local-1']))->allows('dashboard.view'));
    }

    public function test_an_organization_without_a_token_falls_through_too(): void
    {
        Http::fake();
        Gate::define('dashboard.view', fn (): bool => true);

        $user = new GenericUser(['id' => 'u-1', 'console_organization_id' => 'org-1']);

        $this->assertTrue(Gate::forUser($user)->allows('dashboard.view'));
        Http::assertNothingSent();
    }

    public function test_a_token_cleared_during_refresh_falls_through_instead_of_denying(): void
    {
        Http::fake();
        Gate::define('dashboard.view', fn (): bool => true);

        // Người dùng có ngữ cảnh khi Gate::before bắt đầu, nhưng token biến mất
        // sau bước ensureFresh (refresher/model của consumer làm rỗng nó). Đó
        // vẫn là "không phân giải được", không phải "bị từ chối".
        $user = new VanishingTokenUser([
            'id' => 'u-1',
            'console_access_token' => 'at-1',
            'console_organization_id' => 'org-1',
        ]);

        $this->assertTrue(Gate::forUser($user)->allows('dashboard.view'));
        Http::assertNothingSent();
    }

    public function test_an_authoritative_platform_denial_is_not_overridable_by_a_local_policy(): void
    {
        Http::fake([
            '*' => Http::response(['permissions' => ['dashboard.view'], 'roles' => [], 'authoritative' => true]),
        ]);
        Gate::define('employees.delete', fn (): bool => true);

        $user = new GenericUser([
            'id' => 'u-1',
            'console_access_token' => 'at-1',
            'console_organization_id' => 'org-1',
        ]);

        $this->assertFalse(Gate::forUser($user)->allows('employees.delete'));
    }

    public function test_abilities_outside_the_catalog_were_always_a_fall_through(): void
    {
        Http::fake();
        Gate::define('local.feature', fn (): bool => true);

        $this->assertTrue(Gate::forUser(new GenericUser(['id' => 'local-1']))->allows('local.feature'));
        Http::assertNothingSent();
    }
}

/**
 * Trả token đúng MỘT lần: lần đọc thứ hai (sau `ensureFresh`) thấy rỗng. Mô
 * phỏng một consumer mà bước làm mới token dọn sạch phiên.
 */
final class VanishingTokenUser extends GenericUser
{
    private int $tokenReads = 0;

    public function __get($key)
    {
        if ($key === 'console_access_token') {
            return ++$this->tokenReads === 1 ? parent::__get($key) : null;
        }

        return parent::__get($key);
    }
}
