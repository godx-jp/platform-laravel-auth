# dxs/laravel-auth

OAuth2/OIDC **downstream SSO client** for GoDX platform services — Authorization Code + PKCE
(BFF cookie pattern), JWKS-verified bearer resource auth, and platform-authoritative
permission checks. Drop-in for **any** Laravel service that authenticates against the GoDX ID
platform (`id.*` / `platform`).

Authorization decisions stay on the platform: the package fetches the user's resolved
permission list and answers `Gate` from it. The service only declares its permission catalog
(pushed up) and provisions its own user records.

## Install

```bash
composer require dxs/laravel-auth:^0.12
php artisan sso:install   # publishes config + users-table migration + authz catalog
php artisan migrate
```

Set the `SSO_*` env values and you are done: routes (`/auth/redirect|callback|logout`),
a fallback named `login` route, and a zero-config JIT provisioner
(`DatabaseUserProvisioner`, writing your `auth.providers.users.model`) are all
registered by the package. Run `php artisan sso:doctor` to verify the two
organization UUIDs before your first login. Publish an app-owned provisioner only when the
mapping needs custom behaviour: `sso:install --provisioner`.

## Reading the current user's authorization

The `Sso` facade exposes the platform-resolved picture Gate can't (it only
answers yes/no). Every read reuses the same cache the Gate uses:

```php
use Dxs\Auth\Facades\Sso;

Sso::user();                       // the authenticated user (or null)
Sso::permissions();                // Collection<string> of platform permission slugs
Sso::roles();                      // list of platform roles (slug/display_name/level)
Sso::can('branches.view');         // bool
Sso::canAll('a', 'b');  Sso::canAny('a', 'b');
Sso::hasRole('manager');
```

Share it to an Inertia/React frontend in one line:

```php
Inertia::share('permissions', fn () => Sso::permissions());
```

## Lifecycle events

- `Dxs\Auth\Events\SsoAuthenticated($user, $claims, $firstLogin)` — after a
  successful callback + login (`$firstLogin` true when the local record was
  just created). Hook it for audit trails, welcome emails, last-login stamps.
- `Dxs\Auth\Events\SsoLoggedOut($user)` — before the session is torn down.

## Protecting resource routes

One alias authenticates the platform bearer AND requires abilities, with
RFC 6750 semantics (401 `invalid_token` vs 403 `insufficient_scope`):

```php
Route::get('/api/branches/{id}', ...)->middleware('sso.can:branches.view');
Route::post('/api/branches', ...)->middleware('sso.can:branches.view,branches.create'); // all required
```

Abilities are answered by the platform-resolved permission list; local
`Gate::define()` still runs for abilities outside it. Plain `sso.auth` +
Laravel's `can:` keeps working if you prefer wiring them separately.

> **New to the platform?** Follow the step-by-step [downstream onboarding guide](docs/onboarding.md) —
> it covers service registration, every env value, the users-table migration, and a
> symptom→cause debugging map collected from a real integration.

The service provider auto-discovers. Publish config if you want to tweak it:

```bash
php artisan vendor:publish --tag=sso-config
```

## Configure (env only)

```dotenv
SSO_ISSUER=https://platform.godx.jp        # IdP origin; everything else is discovered
SSO_SERVICE_SLUG=my-service                 # token `aud` — this ServiceInstance
SSO_CLIENT_ID=ci_xxx
SSO_CLIENT_SECRET=sk_xxx
SSO_ORGANIZATION_CONTEXT_ID=00000000-0000-4000-8000-000000000000 # console org id → /sso/authorize
SSO_ORGANIZATION_ID=01900000-0000-7000-8000-000000000000          # internal organizations.id → token claim (current platform)
SSO_REDIRECT_URI=https://my-service.example/auth/callback
# optional: SSO_SCOPES, SSO_ROUTES_PREFIX, SSO_TOKEN_COOKIE, SSO_AFTER_LOGIN, ...
```

Development bearer bypass is disabled and deny-all by default. If a local test
suite genuinely needs it, enable it only in `local,testing` and bind
`Dxs\Auth\Contracts\ValidatesDevelopmentSubjects` to an application policy:

```dotenv
SSO_DEV_BYPASS=true
SSO_DEV_BYPASS_ENVIRONMENTS=local,testing
SSO_DEV_BYPASS_PREFIX=dev:
# Static alternative to a binding; use stable subject IDs, never emails.
SSO_DEV_BYPASS_SUBJECTS=test-subject-1,test-subject-2
```

The package still rejects the bypass in staging/production and never accepts an
unapproved subject. Do not enable it on an externally reachable environment.

For a multi-tenant downstream, the platform launcher supplies
`organization_context_id` on the downstream URL. The package validates, stores,
and relays that context to the IdP authorization endpoint.

Set `SSO_ALLOW_ORGANIZATION_SWITCHING=true` only when an authenticated user may
select another organization. Reauthorization must still run through
`GET /auth/redirect`; never update the local organization context directly.

> **Inertia consumers:** a downstream endpoint that returns
> `Inertia::location(route('sso.redirect', ...))` intentionally responds with
> `409 Conflict` and an `X-Inertia-Location` header. The Inertia client converts
> that protocol response into a full-page OIDC navigation. The package's own
> `/auth/redirect` route then responds with the normal `302` redirect to the
> IdP. See [organization switching and Inertia's expected 409](docs/onboarding.md#organization-switching-from-an-inertia-app).

## Wire the one app-specific touch-point

The package never writes your `User` model. Bind the `ProvisionsUsers` contract to your own
implementation (map verified token claims → your user row):

```php
// AppServiceProvider::register()
use Dxs\Auth\Contracts\ProvisionsUsers;

$this->app->singleton(ProvisionsUsers::class, \App\Sso\UserProvisioner::class);
```

That is the **entire** integration. `GET /auth/redirect`, `GET /auth/callback`,
`POST /auth/logout`, the `sso.auth` middleware, and the `Gate::before` permission check are all
provided.

## What you get

| Piece | Purpose |
|---|---|
| `GET {prefix}/redirect` | Start Authorization Code + PKCE (S256) |
| `GET {prefix}/callback`  | Verify state/nonce, exchange code, provision user, set `token` cookie |
| `POST {prefix}/logout`   | Clear the session cookie |
| `POST {prefix}/backchannel-logout` | Validate an OIDC logout token and revoke its local session lineage |
| `sso.auth` middleware    | Validate a platform-issued bearer (JWKS/`aud`/`exp`) and resolve the local user |
| `Gate::before`           | Grant an ability iff it is in the platform-resolved permission list |
| `dxs:sync-authz` | Push this service's declared authorization catalog from `config/authz.php` to the platform (see [authz sync](docs/onboarding.md#step-5--sync-the-authorization-catalog)) |

### Authorization catalog sync (`dxs:sync-authz`)

Declare permissions in `config/authz.php`, set `SSO_SERVICE_ID` (service **UUID** for admin
catalog routes; **slug** for the local dev-admin mirror), then sync:

```dotenv
# Local / CI against the dev-admin mirror (first-class today):
SSO_AUTHZ_MODE=dev
SSO_ADMIN_KEY=...          # X-Admin-Key for PUT /api/dev/services/{slug}/authz
SSO_SERVICE_ID=my-service  # instance slug

# Future / platform bearer endpoint (may 401 until the IdP accepts machine credentials):
# SSO_AUTHZ_MODE=admin
# SSO_ADMIN_TOKEN=...
# SSO_AUTHZ_PATH=api/admin/catalog/{service}/authz
```

`php artisan dxs:sync-authz --dry-run` prints the JSON payload; in `dev` mode it also prints
the equivalent `curl`. Use `--if-changed` in schedulers when `sso.sync.authz.auto` is enabled.

## Independence

The package has **zero** consumer coupling — the only app-facing symbol is the `ProvisionsUsers`
interface. `composer test` boots the provider in a bare Laravel app (via Testbench) and asserts
routes/middleware/services register with config alone. See `tests/IndependenceTest.php`.

## License

Proprietary — © GoDX / DXS platform.
