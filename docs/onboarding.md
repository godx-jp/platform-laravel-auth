# Onboarding a downstream Laravel app onto platform SSO

This guide walks a fresh Laravel app through a complete `dxs/laravel-auth`
integration against the GoDX platform IdP — from registering the service to a
working browser login with JIT-provisioned users. Every step and every gotcha
below was hit for real while onboarding a consumer (`gino-cloud` at
`https://ql.test`) against a local platform at `https://platform.test`.

Time budget: ~30 minutes when nothing surprises you.

## Prerequisites

- A running platform (locally: Herd/Valet at `https://platform.test`, seeded).
- A Laravel 11+ app served over **HTTPS** (`herd secure` — redirect URIs are
  exact-match, and the IdP will not downgrade to `http`).
- Composer access to this package:

```jsonc
// composer.json
"repositories": [
    { "type": "vcs", "url": "https://github.com/dxs-platform/laravel-auth.git" }
]
```

```bash
composer require "dxs/laravel-auth:^0.12"
```

v0.12.0 is the minimum version for authenticated organization switching and
the current downstream context contract. Older releases do not include the
multi-organization reauthorization and context hardening documented here.

## Step 1 — Register the service + instance on the platform

Locally, use the **dev-admin API** (`APP_ENV=local` only; key from
`config/dev-admin.php`, env `DXS_DEV_ADMIN_API_KEY`). There is no artisan
command or `gxa` command that mints a service instance today.

```bash
BASE=https://platform.test
KEY=<dev-admin key>

# 1a. The catalog Service
curl --fail-with-body -X POST "$BASE/api/dev/services" \
  -H "X-Admin-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{
    "slug": "my-service",
    "name": "My Service",
    "default_base_url": "https://my-app.test",
    "default_redirect_uris": ["https://my-app.test/auth/callback"]
  }'

# 1b. The ServiceInstance — this is the OAuth client
curl --fail-with-body -X POST "$BASE/api/dev/services/my-service/instances" \
  -H "X-Admin-Key: $KEY" -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d '{
    "name": "My Service (Local)",
    "slug": "my-service-local",
    "environment": "local",
    "deployment_type": "cloud",
    "organization_id": "<internal Organization id — see gotcha below>",
    "base_url": "https://my-app.test",
    "allowed_redirect_uris": ["https://my-app.test/auth/callback"]
  }'
```

The `201` response contains `client_id` (`si_…`) and `client_secret` (`sk_…`).
**The secret is shown exactly once** — store it immediately.

### Gotchas at this step

- **Slugs are `[a-z0-9-]` only.** A reverse-domain name like
  `jp.example.my-service` is rejected by the validation regex (dots). Keep the
  dotted form as the display `name`; hyphenate the slug.
- **`organization_id` here is the platform-internal `organizations.id`**, not
  the console organization id. If you pass an unknown id you get a validation
  error; look the org up first (`gxa org list`, tinker, or the dev-admin API).
- **The instance is born `provision_status=pending` — logins will fail with
  `error=access_denied`** at the authorize step until it is `ready`
  (`ServiceLaunchPolicy` requires it). Locally, flip it:

  ```php
  ServiceInstance::where('slug', 'my-service-local')
      ->first()->forceFill(['provision_status' => 'ready'])->save();
  ```

- **Every logging-in user needs a `ServiceUserAccess` row** (org + service +
  user) — no grant, no login (`access_denied` again). Grant at least your test
  user. The user must also be **active, email-verified and a member of the
  organization**; seeded local accounts differ here (one of ours had password
  `password`, was unverified and not an org member — pick a user that passes
  all three or fix the record).

## Step 2 — Configure the consumer app

```dotenv
# .env
SSO_ISSUER=https://platform.test
SSO_SERVICE_SLUG=my-service-local          # the INSTANCE slug = access-token audience
SSO_CLIENT_ID=si_...
SSO_CLIENT_SECRET=sk_...
SSO_REDIRECT_URI=https://my-app.test/auth/callback
SSO_SCOPES="openid profile email offline_access"

# TWO different UUIDs for the SAME organization — do not mix them up:
SSO_ORGANIZATION_CONTEXT_ID=<console organization id>   # sent to /sso/authorize
SSO_ORGANIZATION_ID=<internal organization id>          # validated against the token's organization_id claim

SSO_AFTER_LOGIN=/dashboard
SSO_AFTER_LOGOUT=/
# optional: where failed logins land (falls back to SSO_AFTER_LOGOUT, then /)
# SSO_FAILURE_REDIRECT=/login
# SSO_FAILURE_QUERY_PARAMETER=error # for a separately hosted SPA/BFF frontend
```

Why two organization values: the authorize request carries the **console**
organization id (`organization_context_id`), but the platform currently stamps
the instance's **internal** organization id into the access token as
`organization_id`. The package validates whichever claim arrives (legacy
`organization_context_id` takes precedence; `organization_id` requires
`SSO_ORGANIZATION_ID` to be set).

The package auto-registers `GET /auth/redirect`, `GET /auth/callback`,
`POST /auth/logout`, `POST /auth/backchannel-logout` (prefix configurable via
`SSO_ROUTES_PREFIX`).

## Step 3 — users table + provisioner

Add the identity columns (keep them **out of `$fillable`**; the SSO path
writes them via `forceFill` after JWKS verification):

```php
Schema::table('users', function (Blueprint $table): void {
    $table->string('password')->nullable()->change();   // SSO-only users have none
    $table->string('console_user_id', 64)->nullable()->unique();  // token `sub`
    $table->uuid('console_organization_id')->nullable();
    $table->text('console_access_token')->nullable();
    $table->text('console_refresh_token')->nullable();
    $table->timestamp('console_token_expires_at')->nullable();
});
```

Implement `Dxs\Auth\Contracts\ProvisionsUsers` (JIT upsert keyed on
`sub → console_user_id`) and bind it:

```php
// AppServiceProvider::register()
$this->app->singleton(ProvisionsUsers::class, UserProvisioner::class);
```

`$claims` includes `sub`, `organization_id`, and — merged from the verified ID
token — `name` and `email` (RFC 9068 access tokens carry authorization claims
only, so the profile fields ride in the ID token; the package ≥0.4.0 surfaces
them for you).

Point your app's login entry at the package:

```php
Route::redirect('/login', '/auth/redirect')->name('login');
```

Laravel's `auth` middleware then bounces guests → `/login` → the IdP, and the
callback logs them in on the standard `web` session guard.

## Step 4 — Verify end-to-end

1. `GET https://my-app.test/auth/redirect` → 302 to
   `https://platform.test/sso/authorize?...&code_challenge_method=S256`.
2. Log in at the platform (locally the flow continues automatically via the
   stored intended URL).
3. Authorize → 302 back to `/auth/callback?code=…&state=…`.
4. Callback → 302 to `SSO_AFTER_LOGIN`; a `users` row exists with
   `console_user_id`, `name`, `email` filled.
5. Deny-path: hitting `/auth/callback?error=access_denied&state=<valid>` must
   redirect to your failure route with `sso.error` flashed — not a 500.

## Organization switching from an Inertia app

A multi-organization downstream must re-run Authorization Code + PKCE when the
user changes organization. Do not update `console_organization_id`, roles, or
permissions locally: the callback must receive and verify a token bound to the
selected organization first.

Enable the authenticated organization override explicitly:

```dotenv
SSO_ALLOW_ORGANIZATION_SWITCHING=true
```

Keep this disabled for fixed single-tenant services. When a fixed
`SSO_ORGANIZATION_CONTEXT_ID` is configured, the package accepts a different
query value only when this flag is enabled and the downstream user is already
authenticated. An initial multi-tenant launch may supply the context when no
fixed context is configured; the IdP remains authoritative for access. A
malformed UUID always fails closed. Before starting an authenticated switch,
the downstream should also verify that the selected UUID appears in
`Sso::organizations()` for the current access token.

An Inertia downstream commonly uses a server-owned POST endpoint for that
validation and then starts a full browser navigation:

```php
use Dxs\Auth\Facades\Sso;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Symfony\Component\HttpFoundation\Response;

public function __invoke(Request $request): Response
{
    $validated = $request->validate([
        'organization_id' => ['required', 'uuid'],
    ]);

    abort_unless(
        collect(Sso::organizations())->contains(
            fn (array $organization): bool =>
                ($organization['organization_id'] ?? null) === $validated['organization_id'],
        ),
        403,
    );

    return Inertia::location(route('sso.redirect', [
        'organization_context_id' => $validated['organization_id'],
        'return' => '/dashboard',
    ]));
}
```

The React client submits the selection as an Inertia visit:

```tsx
router.post('/organization-context', {
    organization_id: selectedOrganizationId,
})
```

### Why the POST shows `409 Conflict`

This is an Inertia protocol redirect, not an SSO denial:

```http
HTTP/2 409 Conflict
X-Inertia-Location: https://downstream.example/auth/redirect?organization_context_id=...
```

The expected browser sequence is:

```text
POST /organization-context
  -> 409 + X-Inertia-Location (generated by Inertia::location)
  -> GET /auth/redirect (provided by dxs/laravel-auth)
  -> 302 to the IdP authorization endpoint
  -> callback with code + state
  -> verified token and redirect to the local return path
```

The `409` may appear red in browser developer tools even when the flow is
working. Do not change it to `200`, and do not treat it as an authorization
error. A real failure is present only when the Inertia client does not perform
the next full-page visit, the response lacks `X-Inertia-Location`, or the IdP
returns an OAuth error such as `access_denied`.

`curl` cannot execute the Inertia client and does not automatically follow
`X-Inertia-Location` (including when `-L` is used). Inspect the protocol response
without copying live session cookies into tickets or chat:

```bash
curl --include \
  -H 'X-Inertia: true' \
  -H 'Content-Type: application/json' \
  -H 'X-XSRF-TOKEN: <URL-decoded XSRF token>' \
  --cookie 'XSRF-TOKEN=<encrypted token>; laravel-session=<session>' \
  --data '{"organization_id":"<uuid>"}' \
  https://downstream.example/organization-context
```

Use disposable local credentials or a cookie jar and revoke the session after
debugging; never paste live cookies or bearer tokens into tickets or chat. For
an authenticated request, confirm the response has both status `409` and
`X-Inertia-Location`. Verify the complete behavior with a real browser test:
select the organization, assert navigation reaches the authorization endpoint,
assert `organization_context_id`, `response_type=code`, and
`code_challenge_method=S256`, then complete the callback and assert the browser
returns to the downstream with the new organization context.

If the browser remains on the old page, check these in order:

1. The response contains `X-Inertia-Location` and it was not removed by a proxy.
2. The request was made by the official Inertia router, not a plain JSON client.
3. No `router.on('location', ...)` listener cancels the navigation.
4. The browser is running the current compiled frontend assets.
5. The destination `/auth/redirect` returns `302`; only the Inertia bridge uses
   `409`.

### Debugging map (symptom → cause)

| Symptom | Cause |
| --- | --- |
| organization switch POST shows `409` with `X-Inertia-Location` | expected Inertia full-page redirect; the client should continue to `/auth/redirect` |
| organization switch POST shows `409` without `X-Inertia-Location` | malformed/non-Inertia response or a proxy stripped the header; the browser cannot continue |
| `curl -L` stops at the organization switch POST | expected: curl follows `Location`, not Inertia's `X-Inertia-Location` |
| authorize → `?error=access_denied` | `ServiceLaunchPolicy`: instance not `ready`, missing `ServiceUserAccess`, user unverified / not an org member, or org/service inactive |
| callback 500 `state mismatch` | expired/double-used transaction (back button, bookmark) — benign; ≥0.4.0 turns this into a redirect + flash |
| callback: `token organization … does not match` | wrong `SSO_ORGANIZATION_ID` (you probably used the console org id — it needs the internal one) |
| provisioned user has empty name/email | package <0.4.0 (ID-token claims were dropped) |
| `redirect_uri` rejected | exact-match: scheme, host, path, trailing slash must all match the registered URI (`https` vs `http` counts) |

## Step 5 — Sync the authorization catalog

Declare permissions/roles in `config/authz.php` (see the package README), then:

```bash
php artisan dxs:sync-authz --dry-run   # inspect the payload
```

Known platform-side caveats for the real sync (as of 2026-07):

- `SSO_SERVICE_ID` must be the **Service UUID** (route-model binding on
  `api/admin/catalog/{service}` binds by id, not slug).
- The `api/admin/*` surface authenticates the **admin-web BFF session**, not a
  bearer token — so `dxs:sync-authz` with `SSO_ADMIN_TOKEN` may 401 against
  current platforms. Locally, the dev-admin mirror accepts the same manifest
  by **slug** with the admin key:

  ```bash
  php artisan dxs:sync-authz --dry-run | tail -n +2 > authz.json
  curl -X PUT "$BASE/api/dev/services/my-service/authz" \
    -H "X-Admin-Key: $KEY" -H 'Content-Type: application/json' \
    --data-binary @authz.json
  ```

- Verify with the admin CLI: `gxa service permissions list <service-uuid>` /
  `gxa service roles list <service-uuid>` (requires a platform with the CLI
  route-binding fix; before it, these always printed `[]`).

## Reference: platform endpoints involved

| Purpose | Endpoint |
| --- | --- |
| OIDC discovery | `GET /.well-known/openid-configuration` |
| JWKS | `GET /.well-known/jwks.json` |
| Authorize | `GET /sso/authorize` (extras: `service_slug`, `organization_context_id`) |
| Token | `POST /api/sso/token` |
| End session | `GET|POST /sso/logout` |
| Dev-admin service registration | `POST /api/dev/services`, `POST /api/dev/services/{slug}/instances` |
| Dev-admin authz manifest | `PUT /api/dev/services/{slug}/authz` |
