# Requirements coverage

Assessed against [`soca-plugins/requirements.md` at `60ea4db827457b4a4a7b11d79e86b654612a75e1`](https://github.com/RESOAuth/soca-plugins/blob/60ea4db827457b4a4a7b11d79e86b654612a75e1/requirements.md).
Plugin version: **0.1.0-alpha.1**. Assessment/result date: **2026-10-21**.
This is an alpha assessment, not a certification or a production-ready release.
Supported means the stated bounded capability is implemented and has fixture evidence;
partial and planned rows retain the full target requirement without weakening it.

Evidence: [xUnit security fixtures](../tests/RESOAuth.Soca.Umbraco.Tests/SecurityTests.cs), [native demo](../demo/Program.cs), [dated results](verification.md), [operations](operations.md),
[threat model](threat-model.md). Each row applies to this plugin version and date.

| ID | Status | Version | Evidence and remaining gap |
| --- | --- | --- | --- |
| F-01 | Partial | 0.1.0-alpha.1 | Exact discovery, isolated named profiles and explicit capability checks. Actual RESOAuth interoperability awaits a dated real login. |
| F-02 | Partial | 0.1.0-alpha.1 | Code flow, PKCE S256, independent state/nonce and ES256 private_key_jwt. Native handler/configuration fixtures pass; adversarial signed-token vectors and provider/browser conformance remain. |
| F-03 | Partial | 0.1.0-alpha.1 | Maintained ASP.NET Core handler validates tokens and nonce. Exact RFC9207 iss, pinned ES256 and configured assurance checks are added. UserInfo retrieval is disabled; provider semantics and full adversarial token vectors remain gaps. |
| F-04 | Partial | 0.1.0-alpha.1 | Public hosted CIMD/JWKS, application identity defaults and explicit HTTPS branding/legal overrides. Automated discovery of every host legal-page convention is incomplete. |
| F-05 | Partial | 0.1.0-alpha.1 | Default/custom path-only proxy templates, sorted compact UTF-8 JSON and unpadded base64url, document equality and hard size limits. Provider/proxy cache and URL limits require live confirmation; GUI reset remains planned. |
| F-06 | Supported | 0.1.0-alpha.1 | Only public keys/client metadata are published. Both inline jwks and jwks_uri are supported; public proxy disclosure documented and tested. |
| F-07 | Partial | 0.1.0-alpha.1 | Revision changes invalidate candidate evidence and pending callbacks. Automatic overlapping rotation, stable proxy key indirection and an identity migration wizard are planned. |
| F-08 | Partial | 0.1.0-alpha.1 | Owner-only deployment P-256 key reference and native Data Protection for encrypted state. Shared protected Data Protection keys are required across workers. Non-exportable KMS/HSM and automated restore drills are planned. |
| F-09 | Planned | 0.1.0-alpha.1 | Unattended overlapping rotation, cache warming, atomic promotion and monitoring are not implemented. Never replace keys as routine maintenance without a controlled migration. |
| F-10 | Partial | 0.1.0-alpha.1 | ES256/P-256 is pinned independently for signing and verification, with algorithm/key checks. ES384/ES512/PS*/RS256/fully specified EdDSA/ML-DSA and migration vectors remain planned. |
| F-11 | Partial | 0.1.0-alpha.1 | Fresh bounded duplicate-free discovery/JWKS per native handler request, no stale/last-known-good cache or unknown-key retry. Provider revocation feeds and exhaustive rollover fault tests remain planned. |
| F-12 | Partial | 0.1.0-alpha.1 | Verified boolean email, default deny, strict exact/wildcard DNS rules and deny precedence. Native host permissions remain separate. A dedicated preview and sensitive-account policy UI remain planned. |
| F-13 | Partial | 0.1.0-alpha.1 | Umbraco native external links use a SHA-256 namespace of the exact configured issuer and subject. Auto-email linking is disabled for both surfaces. Native eligibility/disabled checks apply; real-provider linked-session checks remain. |
| F-14 | Planned | 0.1.0-alpha.1 | Automatic provisioning is deliberately rejected by configuration validation. Backoffice users and members must exist and have a locally approved native external association. Atomic low privilege provisioning is not implemented. |
| F-15 | Partial | 0.1.0-alpha.1 | Existing local roles and privileges are preserved. No claim-driven elevation. Allowlisted role synchronisation and bounded revocation of existing SSO sessions are planned. |
| F-16 | Partial | 0.1.0-alpha.1 | Persistent native external login records, with issuer-bound subject keys and native locally authenticated linking. Administrator preapproval can use native manager APIs. A packaged approval/migration CLI and end-to-end recovery tests remain planned. |
| F-17 | Partial | 0.1.0-alpha.1 | No silent issuer/subject/email relinking. Explicit unlink/reapproval is required for migrations. Batch migration previews, pairwise-subject continuity and recovery drills remain planned. |
| F-18 | Planned | 0.1.0-alpha.1 | Profile claims are available transiently to validation but are not written into local fields. UserInfo/profile synchronisation, preview and custom mapping are not implemented. |
| F-19 | Planned | 0.1.0-alpha.1 | No claim-inspection capture is implemented. Routine code never dumps tokens/claims. Operator-bound encrypted diagnostic reports and automatic expiry remain planned. |
| F-20 | Partial | 0.1.0-alpha.1 | Deployment configuration is authoritative and read-only in an existing backoffice dashboard. Separate document/test evidence gates activation. Candidate completion requires the same authenticated native local admin and does not sign in the external account. Full live-operator browser validation, stale-edit/rollback automation and CLI wrappers remain gaps. |
| F-21 | Partial | 0.1.0-alpha.1 | Native host sign-in/session/MFA and local logout are used. RP/back-channel logout, bounded SSO-session revocation and complete browser/loop tests remain planned. |
| F-22 | Partial | 0.1.0-alpha.1 | Deployment/environment emergency disable blocks ordinary/test SSO, skips broken keys during startup and preserves native local recovery. Pending state is invalidated after native readiness; fresh missing-key recovery is container-tested. Existing-session revocation and recovery drills remain gaps. |
| F-23 | Partial | 0.1.0-alpha.1 | Native install/schema/auth/permission APIs and transaction cleanup. Disable invalidates transactions through provided maintenance actions. Existing-session revocation, uninstall preservation/export and rolling upgrade drills remain gaps. |
| F-24 | Supported | 0.1.0-alpha.1 | No offline scope or retained refresh/access/ID token. Ordinary admission requests openid email. Codes and transient tokens are discarded after exchange. |
| F-25 | Partial | 0.1.0-alpha.1 | Native encrypted Data Protection state protects verifier/nonce and native Secure/HttpOnly/Lax correlation/nonce cookies bind the browser. A minimal host database replay record adds atomic one-use consumption. Native session behaviour needs live browser confirmation. |
| N-01 | Partial | 0.1.0-alpha.1 | Maintained JWT/cryptographic/host facilities, strict defaults and documented threat model. Independent security review and full conformance remain outstanding. |
| N-02 | Partial | 0.1.0-alpha.1 | HTTPS/TLS, DNS cancellation and all-address validation, pinned socket addresses preserving TLS, bounded buffered bodies, 15-second HTTP deadline and no redirects/environment proxies. Exhaustive mixed DNS, IPv6 and slow-response fault testing remain gaps. |
| N-03 | Partial | 0.1.0-alpha.1 | Minimal identity links and encrypted short-lived transactions, deployment-managed keys, no plugin token/claim logs. Reverse-proxy/host access-log redaction and backup deletion must be configured by the operator. |
| N-04 | Partial | 0.1.0-alpha.1 | Database uniqueness and atomic transaction consumption support shared workers. Failover, restore, rolling upgrades and availability objectives have not been validated. |
| N-05 | Partial | 0.1.0-alpha.1 | Bounded input/HTTP/state lifetime and scheduled cleanup. Deploy edge rate limits. Sustained abuse/load evidence and numeric capacity objectives remain planned. |
| N-06 | Partial | 0.1.0-alpha.1 | Native settings and labelled login controls, redacted errors and native audit facilities. WCAG 2.2 AA manual audit, tamper-evident records and full security metrics remain planned. |
| N-07 | Partial | 0.1.0-alpha.1 | Licence, install/recovery/security documentation, pinned dependencies/images/workflows, package checks, CI, Dependabot, CodeQL and vulnerability checks. Signed release provenance/SBOM and supported upgrade matrix are planned. |
| N-08 | Partial | 0.1.0-alpha.1 | 52 xUnit security cases, native SQLite host boot/schema migration and replay checks are reproducible. No real provider login, multi-worker SQL Server/SQLite stress suite, OIDC certification or independent review is claimed. |
| N-09 | Partial | 0.1.0-alpha.1 | This complete per-ID alpha assessment and dated evidence are published. Provider cache bounds, broader algorithm/surface matrices and all acceptance criteria remain incomplete. |
