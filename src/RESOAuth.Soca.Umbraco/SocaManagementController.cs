using System.Security.Claims;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Umbraco.Cms.Web.Common.Authorization;

namespace RESOAuth.Soca.Umbraco;

[ApiController]
[Route("umbraco/management/api/v1/soca")]
[Authorize(Policy = AuthorizationPolicies.RequireAdminAccess)]
public sealed class SocaManagementController(SocaOptions options, ISocaStore store, IAntiforgery antiforgery, IOptions<AntiforgeryOptions> antiforgeryOptions) : ControllerBase
{
    private SocaProfile Profile(string name, string surface) => options.Profiles.Single(x => x.Name == name && x.Surface == surface);

    [HttpGet("csrf")]
    public IActionResult Csrf()
    {
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        return Ok(new { token = tokens.RequestToken, header = antiforgeryOptions.Value.HeaderName ?? "RequestVerificationToken" });
    }

    [HttpGet]
    public IActionResult Status() => Ok(options.Profiles.Select(StatusProfile));

    private object StatusProfile(SocaProfile profile)
    {
        if (options.IsEmergency(profile)) return new { profile.Name, profile.Surface, enabled = false, emergencyDisabled = true, source = "Emergency recovery: SOCA providers and public metadata are not registered." };
        return new
    {
        profile.Name, profile.Surface, profile.Enabled, profile.ClientId, profile.Fingerprint,
        emergencyDisabled = options.EmergencyDisabled || profile.EmergencyDisabled,
        documentChecked = store.HasEvidence("document", profile.Fingerprint),
        liveTestPassed = store.HasEvidence("login", profile.Fingerprint),
        source = "Deployment configuration. All fields locked in the GUI."
    };
    }

    [ValidateAntiForgeryToken]
    [HttpPost("{name}/{surface}/check")]
    public async Task<IActionResult> Check(string name, string surface, CancellationToken ct)
    {
        var profile = Profile(name, surface);
        if (options.IsEmergency(profile)) return Conflict("SOCA emergency disabled");
        using var client = NetworkGuard.Client();
        using var discovery = await NetworkGuard.Json(client, profile.Issuer.TrimEnd('/') + "/.well-known/openid-configuration", ct);
        Protocol.ValidateDiscovery(profile, new OpenIdConnectConfiguration(discovery.RootElement.GetRawText()));
        using var document = await NetworkGuard.Json(client, profile.ClientId, ct);
        if (!JsonNode.DeepEquals(JsonNode.Parse(document.RootElement.GetRawText()), JsonNode.Parse(SocaProfile.Canonical(profile.Document())))) return BadRequest("Public CIMD does not match the candidate");
        if (!profile.InlineJwks)
        {
            using var jwks = await NetworkGuard.Json(client, profile.Origin.TrimEnd('/') + profile.JwksPath, ct);
            if (!JsonNode.DeepEquals(JsonNode.Parse(jwks.RootElement.GetRawText()), JsonNode.Parse(SocaProfile.Canonical(new { keys = new[] { profile.PublicJwk() } })))) return BadRequest("Public JWKS does not match");
        }
        store.RecordEvidence("document", profile.Fingerprint);
        return Ok(new { document = "passed", revision = profile.Fingerprint, login = "real candidate test required" });
    }

    [ValidateAntiForgeryToken]
    [HttpPost("{name}/{surface}/test")]
    public async Task<IActionResult> Test(string name, string surface)
    {
        var profile = Profile(name, surface);
        if (options.IsEmergency(profile)) return Conflict("SOCA emergency disabled");
        // API access tokens and the native login cookie can use different claim
        // representations. Bind both ends to the same validated native cookie.
        var local = await HttpContext.AuthenticateAsync(global::Umbraco.Cms.Core.Constants.Security.BackOfficeAuthenticationType);
        var operatorId = local.Principal?.FindFirstValue(ClaimTypes.NameIdentifier) ?? local.Principal?.FindFirstValue("sub");
        if (!Protocol.OperatorMatches(local.Principal, operatorId)) return Forbid();
        var properties = new AuthenticationProperties { RedirectUri = "/umbraco/" };
        properties.Items["soca.test"] = operatorId;
        // Generate native encrypted state and correlation/nonce cookies, then return the
        // resulting redirect to the existing backoffice dashboard for browser navigation.
        await HttpContext.ChallengeAsync(profile.Scheme, properties);
        var target = Response.Headers.Location.ToString();
        Response.Headers.Remove("Location"); Response.StatusCode = 200;
        return Ok(new { url = target });
    }

    [ValidateAntiForgeryToken]
    [HttpPost("invalidate")]
    public IActionResult Invalidate() { store.Invalidate(); return Ok(new { pendingTransactions = "invalidated" }); }
}
