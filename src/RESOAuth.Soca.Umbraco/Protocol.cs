using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Umbraco.Cms.Core;

namespace RESOAuth.Soca.Umbraco;

public static class Protocol
{
    public static void Configure(OpenIdConnectOptions options, SocaProfile profile, SocaOptions all)
    {
        options.Authority = profile.Issuer;
        options.ClientId = profile.ClientId;
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.ResponseMode = OpenIdConnectResponseMode.Query;
        options.UsePkce = true;
        options.SaveTokens = false;
        options.MapInboundClaims = false;
        options.GetClaimsFromUserInfoEndpoint = false;
        options.CallbackPath = profile.CallbackPath;
        options.RemoteSignOutPath = PathString.Empty;
        options.SignedOutCallbackPath = profile.CallbackPath + "-signedout";
        options.RequireHttpsMetadata = true;
        options.DisableTelemetry = true;
        options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;
        options.RemoteAuthenticationTimeout = TimeSpan.FromMinutes(5);
        options.MaxAge = profile.MaxAgeSeconds is int age ? TimeSpan.FromSeconds(age) : null;
        options.Scope.Clear(); options.Scope.Add("openid"); options.Scope.Add("email");
        options.Backchannel = NetworkGuard.Client();
        options.ConfigurationManager = new SocaConfigurationManager(profile, options.Backchannel);
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true, ValidIssuer = profile.Issuer, ValidateAudience = true, ValidAudience = profile.ClientId,
            ValidateLifetime = true, RequireSignedTokens = true, RequireExpirationTime = true,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256], ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "name", RoleClaimType = "soca_unmapped_roles",
            AlgorithmValidator = (algorithm, key, token, parameters) => algorithm == SecurityAlgorithms.EcdsaSha256 && (key is JsonWebKey jwk && jwk.Kty == "EC" && jwk.Crv == "P-256" && string.IsNullOrEmpty(jwk.D) || key is ECDsaSecurityKey ec && ec.KeySize == 256)
        };
        options.ProtocolValidator.RequireNonce = true;
        options.ProtocolValidator.NonceLifetime = TimeSpan.FromMinutes(5);
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.HttpOnly = true;
        options.CorrelationCookie.SameSite = SameSiteMode.Lax;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.NonceCookie.HttpOnly = true;
        options.NonceCookie.SameSite = SameSiteMode.Lax;
        options.RefreshOnIssuerKeyNotFound = false;
        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = async context =>
            {
                Available(context.HttpContext, profile, all, context.Properties.Items.ContainsKey("soca.test"));
                if (!context.Request.IsHttps) throw new InvalidOperationException("HTTPS required for SOCA");
                var discovery = await options.ConfigurationManager!.GetConfigurationAsync(context.HttpContext.RequestAborted);
                ValidateDiscovery(profile, discovery);
                context.ProtocolMessage.RedirectUri = profile.Callback;
                if (profile.RequiredAcr.Length > 0) context.ProtocolMessage.AcrValues = string.Join(' ', profile.RequiredAcr);
                var tx = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
                context.Properties.Items["soca.tx"] = tx;
                context.Properties.Items["soca.revision"] = profile.Fingerprint;
                context.Properties.Items["soca.iss_required"] = "true";
                context.HttpContext.RequestServices.GetRequiredService<ISocaStore>().Insert("tx:" + SocaProfile.Hash(tx), profile.Fingerprint, DateTime.UtcNow.AddMinutes(5));
            },
            OnMessageReceived = context =>
            {
                try
                {
                    Available(context.HttpContext, profile, all, context.Properties?.Items.ContainsKey("soca.test") == true);
                    if (!context.Request.IsHttps || context.Properties is null || !context.Properties.Items.TryGetValue("soca.tx", out var tx) || tx is null || Value(context.Properties, "soca.revision") != profile.Fingerprint || context.HttpContext.RequestServices.GetRequiredService<ISocaStore>().Consume("tx:" + SocaProfile.Hash(tx)) != profile.Fingerprint)
                        throw new InvalidOperationException("Expired, replayed or changed SOCA transaction");
                    var issuer = context.ProtocolMessage.GetParameter("iss");
                    if (issuer is not null && issuer != profile.Issuer || Value(context.Properties, "soca.iss_required") == "true" && issuer != profile.Issuer)
                        throw new InvalidOperationException("SOCA response issuer mismatch");
                }
                catch { context.Fail("SOCA transaction rejected"); }
                return Task.CompletedTask;
            },
            OnAuthorizationCodeReceived = context =>
            {
                var now = DateTime.UtcNow;
                using var key = profile.SigningKey();
                var signing = new ECDsaSecurityKey(key) { KeyId = (string)profile.PublicJwk()["kid"] };
                var assertion = new JwtSecurityToken(profile.ClientId, profile.Issuer,
                    [new Claim("sub", profile.ClientId), new Claim("jti", Guid.NewGuid().ToString("N"))], now, now.AddSeconds(60), new SigningCredentials(signing, SecurityAlgorithms.EcdsaSha256));
                context.TokenEndpointRequest!.ClientSecret = null;
                context.TokenEndpointRequest.ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
                context.TokenEndpointRequest.ClientAssertion = new JwtSecurityTokenHandler().WriteToken(assertion);
                context.TokenEndpointRequest.RedirectUri = profile.Callback;
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                try
                {
                    var claims = context.Principal!;
                    var subjects = claims.FindAll("sub").ToArray();
                    if (subjects.Length != 1 || subjects[0].Value.Length is < 1 or > 255 || !subjects[0].Value.All(x => x is >= ' ' and <= '~'))
                        throw new InvalidOperationException("Invalid SOCA subject");
                    Admission.Evaluate(profile, claims, DateTimeOffset.UtcNow);
                    // Email is never a local account selector. Native external login key is issuer-bound.
                    var identity = (ClaimsIdentity)claims.Identity!;
                    foreach (var old in identity.FindAll(ClaimTypes.NameIdentifier).ToArray()) identity.RemoveClaim(old);
                    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, SocaProfile.ProviderKey(profile.Issuer, subjects[0].Value)));
                }
                catch { context.Fail("SOCA identity or admission rejected"); }
                return Task.CompletedTask;
            },
            OnTicketReceived = async context =>
            {
                // This event follows native signature, nonce, correlation and token-response validation.
                if (context.Properties?.Items.ContainsKey("soca.test") == true)
                {
                    var local = await context.HttpContext.AuthenticateAsync(Constants.Security.BackOfficeAuthenticationType);
                    if (!OperatorMatches(local.Principal, Value(context.Properties, "soca.test")))
                    {
                        context.Fail("The initiating local administrator session is missing or changed");
                        return;
                    }
                    context.HttpContext.RequestServices.GetRequiredService<ISocaStore>().RecordEvidence("login", profile.Fingerprint);
                    context.HandleResponse(); context.Response.Redirect("/umbraco/");
                }
            },
            OnRemoteFailure = context =>
            {
                context.HandleResponse(); context.Response.StatusCode = 403;
                return context.Response.WriteAsync("SOCA sign-in could not be completed. Use local recovery or contact your administrator.");
            }
        };
    }

    public static bool OperatorMatches(ClaimsPrincipal? principal, string? expected)
    {
        if (principal?.Identity?.IsAuthenticated != true || !principal.IsInRole(Constants.Security.AdminGroupAlias) || string.IsNullOrEmpty(expected)) return false;
        var actual = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? principal.FindFirstValue("sub");
        return actual is not null && actual == expected;
    }

    private static string? Value(AuthenticationProperties properties, string key) => properties.Items.TryGetValue(key, out var value) ? value : null;

    public static void Available(HttpContext context, SocaProfile profile, SocaOptions all, bool test)
    {
        var store = context.RequestServices.GetRequiredService<ISocaStore>();
        if (all.IsEmergency(profile))
        { store.Invalidate(); throw new InvalidOperationException("SOCA emergency disabled"); }
        if (!store.HasEvidence("document", profile.Fingerprint) || !test && (!profile.Enabled || !store.HasEvidence("login", profile.Fingerprint)))
            throw new InvalidOperationException("SOCA requires document checks and a real candidate test before activation");
    }

    public static void ValidateDiscovery(SocaProfile profile, OpenIdConnectConfiguration discovery)
    {
        if (discovery.Issuer != profile.Issuer) throw new InvalidOperationException("Discovery issuer mismatch");
        foreach (var url in new[] { discovery.AuthorizationEndpoint, discovery.TokenEndpoint, discovery.JwksUri }) NetworkGuard.ValidateUrl(url);
        if (!discovery.ResponseTypesSupported.Contains("code") || !discovery.CodeChallengeMethodsSupported.Contains("S256") || !discovery.TokenEndpointAuthMethodsSupported.Contains("private_key_jwt") || !discovery.TokenEndpointAuthSigningAlgValuesSupported.Contains("ES256") || !discovery.IdTokenSigningAlgValuesSupported.Contains("ES256"))
            throw new InvalidOperationException("Provider must support code, S256, private_key_jwt and ES256");
        if (discovery.AdditionalData.TryGetValue("client_id_metadata_document_supported", out var cimd) && cimd.ToString()?.ToLowerInvariant() != "true")
            throw new InvalidOperationException("Provider explicitly does not support CIMD");
    }
}
