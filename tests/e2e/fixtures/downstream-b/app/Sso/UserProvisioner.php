<?php

namespace App\Sso;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;

final class UserProvisioner implements ProvisionsUsers
{
    public function provision(array $claims, array $tokens): Authenticatable
    {
        return $this->user((string) $claims['sub']);
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        return $this->user($subject);
    }

    private function user(string $subject): Authenticatable
    {
        return new GenericUser(['password' => '', 'id' => $subject, 'name' => 'E2E User']);
    }
}
