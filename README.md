# SOCA for Umbraco

A NuGet package registering separate native external login providers for Umbraco
backoffice users and website members, with OIDC code flow, PKCE S256, ES256
private_key_jwt and hosted/proxy CIMD. **Alpha 0.1.0-alpha.1: ordinary SSO defaults off.**
Review the complete [requirements assessment](docs/requirements-coverage.md).

The package uses the maintained ASP.NET Core OIDC handler, native identity/session
facilities and a minimal native database migration for replay/evidence state. A native
Settings dashboard exposes effective configuration plus document/test actions.
Admission denies by default. Native email auto-linking is disabled. Local credentials,
MFA and account permissions remain under Umbraco control. Automatic provisioning is
not implemented and configuration rejects enabling it.

Tested with **Umbraco 17.7.1**, **.NET SDK 10.0.402/runtime 10.0.13**, and SQLite.
SQL Server and other Umbraco majors are not validated. Build/install the package:

```sh
dotnet test tests/RESOAuth.Soca.Umbraco.Tests/RESOAuth.Soca.Umbraco.Tests.csproj
dotnet pack src/RESOAuth.Soca.Umbraco/RESOAuth.Soca.Umbraco.csproj -c Release -o dist
dotnet add YourHost.csproj package RESOAuth.Soca.Umbraco --version 0.1.0-alpha.1 --source ./dist
```

Register `.AddSoca()` on the existing Umbraco builder and call `app.MapSoca()` after
native endpoint setup, as shown in [the demo](demo/Program.cs). Configure the `Soca`
section using [demo/soca.example.json](demo/soca.example.json), absolute owner-only
P-256 key references and a canonical HTTPS origin. Settings remain deployment-locked
and read-only in the backoffice. Persist and protect the host Data Protection keys
across restarts/workers. Add callbacks to the host reserved paths.

Each profile/surface has public `/soca/{name}/{surface}/metadata` and `/jwks` routes,
with an exact `/umbraco/soca/{name}/{surface}/callback` callback. Named backoffice
schemes use `Umbraco.Soca.{name}`; member schemes use `UmbracoMembers.Soca.{name}`.
The exact native external login key is `SocaProfile.ProviderKey(issuer, subject)`.
Use locally authenticated native external-link management or independently approved
native manager APIs, never email-based ownership inference.

Publish/check candidate documents while disabled. From the existing Settings > SOCA
dashboard, initiate a real candidate login, then enable only after both checks pass.
The callback requires the same authenticated local administrator cookie; missing,
logged-out or switched operators fail. Candidate tests do not create/link users or
replace the operator session. This exact browser/provider flow still needs a live
staging verification. Local administrator login remains enabled.

[Configuration and recovery](docs/operations.md) cover every supported setting,
limits, headless deployment/API operations and emergency disable. The authorised
management API is `/umbraco/management/api/v1/soca` with per-profile check/test actions.
Proxy mode defaults to `https://dynamic-cimd.resoauth.cloud/cimd/%s`; encoded metadata
is public. Use InlineJwks=true when the application has no public key endpoint.

The [demo Containerfile](Containerfile) builds and tests the package, then starts a
real native Umbraco/SQLite host. `bash demo/test-host.sh` runs a disposable installed
host with native replay checks and verifies the backoffice and protected API. The
unattended demo administrator password is generated per run, not committed. Normal
SSO remains disabled. For manual HTTPS staging, mount key/config files and use the
host's normal trusted HTTPS/reverse-proxy configuration.

[Dated verification](docs/verification.md) records synthetic tests, native boot/schema
checks and unattempted provider logins separately. Broad algorithms, automated rotation,
provisioning, profile/role mapping, diagnostic capture, provider/back-channel logout,
bounded existing-session revocation and full browser/conformance/accessibility review
remain gaps. This alpha is not a production-ready authentication certification.

See [SECURITY.md](SECURITY.md), [threat model](docs/threat-model.md),
[AGPL-3.0-only licence](LICENSE) and Umbraco's official
[external login provider documentation](https://docs.umbraco.com/umbraco-cms/17.latest/run-in-production/security/external-login-providers).
