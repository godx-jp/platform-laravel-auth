<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Support\ConfigDevelopmentSubjectValidator;
use Orchestra\Testbench\TestCase;

final class ConfigDevelopmentSubjectValidatorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    public function test_it_denies_every_subject_by_default(): void
    {
        $this->assertFalse((new ConfigDevelopmentSubjectValidator)->allows('unconfigured'));
    }

    public function test_it_allows_only_an_explicitly_configured_subject(): void
    {
        config(['sso.dev_bypass.subjects' => ['approved-subject']]);
        $validator = new ConfigDevelopmentSubjectValidator;

        $this->assertTrue($validator->allows('approved-subject'));
        $this->assertFalse($validator->allows('attacker'));
    }
}
