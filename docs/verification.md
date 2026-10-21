# Verification evidence

Result date: **2026-10-21**. Plugin **0.1.0-alpha.1**. Requirements revision:
`60ea4db827457b4a4a7b11d79e86b654612a75e1`.

**Umbraco 17.7.1**, **.NET SDK 10.0.402/runtime 10.0.13**: native compilation
succeeded and **50 xUnit security cases passed**. Cases cover exact/nested/wildcard
DNS semantics and malformed rules; admission default deny/deny precedence; boolean
email verification; ES256 public metadata; deterministic proxy encoding and branding/
legal fields; unsafe hostname/query proxy substitutions; evidence revisions; private,
mixed/special-use IPv4/IPv6 addresses; duplicate JSON; native handler settings; separate
native scheme names; issuer-namespaced identity keys; and absent/changed initiating
local administrators, and native antiforgery protection on all management mutations. These are synthetic unit tests, not real provider logins.

The real native SQLite demo installed **80 native tables**, including the package
`socaSecurityState` replay/evidence migration, and served the native backoffice with
**HTTP 200**. The unauthenticated management API returned **HTTP 401**. The disposable
container fixture additionally exercises native store insertion, atomic consumption,
replay rejection, invalidation and absence of provider-test evidence. The Containerfile
builds/tests the package and runs the published host as the unprivileged native app user.
A second clean host boots with global emergency disable and a missing signing key,
asserting native local backoffice availability and disabled public metadata.

NuGet packaging and public-data checks passed: native assembly, dashboard, package
manifest and transitive native-asset copy targets are included; no PEM/PFX/database
files are packaged. Current transitive package audit reported **no known high or
critical vulnerabilities**. Patched MessagePack and cryptography dependencies override
older host transitive references. NuGet emits advisory NU1510 about the explicit patched
System.Security.Cryptography.Xml reference; it is retained to keep the locked dependency
graph on the patched version. No signed public NuGet release has been made. CodeQL covers C#, JavaScript, Python tooling
and GitHub Actions.

Reproduction:

```sh
dotnet test tests/RESOAuth.Soca.Umbraco.Tests/RESOAuth.Soca.Umbraco.Tests.csproj -c Release
dotnet pack src/RESOAuth.Soca.Umbraco/RESOAuth.Soca.Umbraco.csproj -c Release -o dist
python3 tools/check-package.py
python3 tools/check-vulnerabilities.py
bash demo/test-host.sh
```

| Provider / metadata / surface | Synthetic evidence | Real provider login |
| --- | --- | --- |
| RESOAuth defaults / hosted / backoffice | Metadata, handler/security and native host fixtures | Not attempted |
| RESOAuth defaults / proxy / backoffice | Deterministic metadata/safety fixtures | Not attempted |
| RESOAuth defaults / hosted / members | Separate native scheme/configuration fixtures | Not attempted |
| RESOAuth defaults / proxy / members | Shared deterministic metadata/safety fixtures | Not attempted |

Real provider credentials were not supplied. The exact native local-operator cookie
behaviour during a candidate callback, linked-user session creation, browser MFA and
assurance, hosted/proxy public reachability, SQL Server/multi-worker fault handling,
OIDC certification, independent review, load and WCAG checks remain unverified.
Provisioning, broad algorithms, automated rotation, profile/role mapping, diagnostics,
provider logout and bounded existing-session revocation remain implementation gaps.
See the [complete per-ID assessment](requirements-coverage.md).
