# Threat model

Protect interactive native backoffice/member sessions and exact issuer/subject
associations. Remote email, usernames and role claims never select or elevate local
accounts. Native email auto-linking and provisioning are disabled. Separate native
schemes/callbacks prevent cross-surface identity confusion. The configured trusted
issuer is never derived from token claims or request headers.

Use the maintained ASP.NET Core OIDC handler and IdentityModel validation. Native
Data Protection protects browser-carried verifier, nonce and state. Native correlation
and nonce cookies provide browser binding; a minimal shared host database digest
provides atomic one-use consumption. A copied callback cannot obtain native binding
cookies. State is bound to the configuration fingerprint, issuer/surface and native
scheme. Candidate testing additionally requires the same local administrator cookie.

Network access validates HTTPS, all resolved IP addresses and response limits before
using maintained discovery/JWKS retrieval. TLS hostname/SNI verification remains on,
with the socket connected to the validated address. Redirects and environment proxies
are disabled. DNS pinning, unusual IPv6 and deadline edge cases require wider review.

Metadata/proxy URLs are public. Signing keys and native Data Protection keys are
separate deployment secrets. No raw authentication tokens or claim diagnostics are
retained by this package. Native host records are not tamper-evident against database
administrators. Provider/host compromise, overly broad operator admission, stolen
local administrator credentials and unprotected backups remain deployment boundaries.

Automated rotation, all algorithm profiles, provisioning, provider/session revocation,
full browser/operator-cookie verification and independent OIDC/security review are
outstanding. The alpha must remain disabled until deployment checks and real candidate
login evidence are complete. Synthetic tests are not live-provider evidence.
