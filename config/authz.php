<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Service authorization catalog
|--------------------------------------------------------------------------
| The permission codes THIS service declares — the permission SCHEMA. The
| service owns this file; the package only reads it, through exactly one
| reader (`Dxs\Auth\Authorization\PermissionCatalog`) so that all three
| consumers agree on what a declaration means.
|
| Each permission: ['slug' => 'group.action', 'display_name' => '...', 'group' => '...'].
| `slug` is required and must match /^[a-z0-9][a-z0-9._-]*$/; `display_name`
| defaults to the slug; `group` may be omitted.
| Roles/assignments are optional and typically managed on the platform.
|
| Who reads it:
|   php artisan dxs:sync-authz   → PUT the catalog UP to the platform
|   php artisan dxs:seed-authz   → write it DOWN into the local permission tables
|   Gate::define                 → one ability per slug, answered from those tables
*/

return [
    'permissions' => [
        // ['slug' => 'absences.view', 'display_name' => 'Absences · View', 'group' => 'absences'],
    ],

    'roles' => [
        // ['role' => 'admin', 'display_name' => 'Administrator', 'level' => 100, 'permissions' => ['absences.view']],
    ],

    'default_role' => null,
];
