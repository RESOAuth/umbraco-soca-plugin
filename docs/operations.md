# Configuration and operations

The NuGet package targets Umbraco 17.7.1 and .NET 10. Backoffice and member login
surfaces have separate native schemes, metadata documents, callbacks, identity links
and candidate evidence. Register the package with `.AddSoca()` and map its public
endpoints using `app.MapSoca()`, as in the native demo. Add callback paths to the
host reserved paths. Canonical HTTPS origin is configured, never inferred from Host
or forwarded headers. Restrict trusted reverse proxies at the host boundary.

`Soca` configuration binds from normal .NET configuration, so environment variables,
appsettings JSON and deployment providers use the host's normal precedence. The
optional `AddSoca(Action<SocaOptions>)` code override runs last. There are no database
settings overrides. All fields are locked in the native SOCA settings dashboard.
The demo can load a deployment JSON file from `SOCA_CONFIG_FILE` after appsettings;
production applications can use their existing host configuration provider instead.

Top-level `EmergencyDisabled` overrides every profile. `SOCA_EMERGENCY_DISABLED=1`,
`true` or `yes` also blocks ordinary and candidate SSO. Each `Profiles` entry supports:
`Name`, `Surface` (backoffice/member), `Issuer`, `Origin`, `ClientName`, `ClientUri`,
`LogoUri`, `PolicyUri`, `TosUri`, `PrivateKeyFile`, `MetadataMode` (hosted/proxy),
`InlineJwks`, `ProxyTemplate`, `AllowEmails`, `DenyEmails`, `AllowDomains`,
`DenyDomains`, `Enabled`, `EmergencyDisabled`, `MaxAgeSeconds`, `RequiredAcr` and
`RequiredAmr`. ProvisionMembers/MemberTypeAlias/MemberGroup are reserved roadmap
settings; enabling provisioning is rejected in this alpha.

The application name defaults to configured ApplicationName or the entry assembly
name. Homepage defaults to the configured public origin. Supply public HTTPS logo,
privacy and terms pages where no unambiguous platform default exists. Privacy policy
and terms are separate fields; unavailable optional URLs are omitted.

Generate the P-256 key with owner-only filesystem permissions, mount it read-only and
set `PrivateKeyFile` to an absolute path. Private keys never enter metadata or forms.
Persist/protect native ASP.NET Core Data Protection keys across all workers and restarts,
using the host's existing supported secret/certificate/KMS protection. A separate
plugin transaction-secret store is unnecessary: verifier/state/nonce are protected by
native encrypted state and correlation cookies. The plugin database stores only random
transaction digests, configuration fingerprints, expiry and activation evidence.

Hosted mode serves CIMD/JWKS anonymously with a 60-second cache lifetime. Proxy mode
replaces one `%s` in the HTTPS path of
`https://dynamic-cimd.resoauth.cloud/cimd/%s` with unpadded base64url of UTF-8 compact
sorted-key public JSON, excluding client_id. Set InlineJwks=true for applications with
no publicly reachable key endpoint. The proxy returns the exact metadata plus the
complete resulting URL as client_id. Encoded metadata and proxy URLs are public.
Payload and URL limits are 4,096 UTF-8 bytes and 8,192 characters respectively.

Every provider must support code flow, PKCE S256, ES256 private_key_jwt and ES256
ID tokens. ES256/P-256 is the only supported algorithm in this alpha. The maintained
ASP.NET Core handler validates signature, issuer, audience, nonce and token lifetime;
algorithm/key checks and exact response iss are added. No UserInfo retrieval,
profile/role synchronisation or auto-email linking occurs. Admission requires a
boolean verified email. Exact/wildcard DNS rules are validated and deny wins.

Ordinary SSO remains disabled until candidate public document checks and a real
operator-bound login have succeeded for the effective fingerprint. Management API
check/test endpoints require native local backoffice administrator authorisation.
The callback authenticates the native backoffice cookie and compares its administrator
ID with the encrypted initiating ID. A missing/logged-out/switched operator fails.
Candidate completion records evidence and returns to the existing backoffice session;
it does not create/link users or sign in the external ticket. Test this browser/cookie
behaviour in your staging deployment before activation. It has no live-provider
verification in the published evidence. Enabling alone preserves candidate evidence;
covered configuration/key/policy changes produce a different fingerprint.

Use native external-login management for existing backoffice users and members, or
approve a link through the native identity manager after independent ownership
verification. The native provider key is `SocaProfile.ProviderKey(exactIssuer, subject)`,
a SHA-256 namespace of the two immutable values. A verified email never proves local
account ownership. Native automatic linking is disabled. New users must be created
and authorised locally; provisioning remains planned.

| Bound | Value / behaviour |
| --- | --- |
| State/correlation/nonce | 300 seconds, native protected state/cookies and database one-use digest |
| Assertion | ES256/P-256, 60 seconds, random jti, issuer audience |
| Clock skew | 30 seconds |
| Fresh authentication | MaxAgeSeconds 0..86,400 when configured; acr/amr meanings need provider verification |
| Metadata body / URL | 4,096 bytes / 8,192 characters |
| HTTPS fetch | 262,144-byte maximum buffered body, 15-second total HTTP timeout, 3-second connect timeout, no redirects/compression |
| DNS | cancellation-aware resolution; reject every mixed/private/special-use answer; pin connection to checked address |
| Discovery/JWKS cache | none; maintained retriever fetches fresh trust per native handler request |
| Public metadata cache | max-age=60; provider/CDN/proxy cache bounds unconfirmed |
| Candidate evidence | fingerprint-bound, expires after 30 days |
| Cleanup | expired state removed on new insertion; consume rejects expired state immediately |
| Rotation overlap | no automated rotation or claimed overlap schedule |
| Existing-session revocation | native host controls; no plugin propagation bound |
| Tokens and diagnostics | SaveTokens=false; no retained refresh/access/ID tokens or claim reports |

Retain independent local administrator credentials and MFA. DenyLocalLogin remains
false. Emergency disable invalidates pending state when observed, and the authorised
`POST /umbraco/management/api/v1/soca/invalidate` action clears pending transactions.
Include invalidation in disable/redeployment procedures, restart workers for deployment
changes and explicitly revoke affected native sessions when required. Local logout
uses host facilities without provider availability. Provider/back-channel logout is
not implemented. Export approved native external login records before changing issuer,
client ID or pairwise subjects. No routine key replacement/rotation is safe to assume;
inline proxy key changes alter client identity and need an explicit migration.

To uninstall, disable/invalidate SSO, remove the package and native dashboard assets,
preserve local users/roles/recovery and export native link records. The minimal SOCA
state table is intentionally preserved; remove it explicitly only after scoped audit
and backup deletion decisions. Restore must not revive pending/revoked transactions.
Suppress callback query strings in host/reverse-proxy access logs and keep IdentityModel
PII logging disabled. Demo logging suppresses request-query and authentication details.
