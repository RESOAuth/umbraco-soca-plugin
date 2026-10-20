using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Umbraco.Cms.Web.Website.Security;
using Microsoft.AspNetCore.WebUtilities;
using RESOAuth.Soca.Umbraco;
using Umbraco.Cms.Api.Management.Security;
using Xunit;

namespace RESOAuth.Soca.Umbraco.Tests;

public sealed class SecurityTests : IDisposable
{
    private readonly string _keyFile;
    public SecurityTests()
    {
        _keyFile = Path.Combine(Path.GetTempPath(), "soca-test-" + Guid.NewGuid().ToString("N") + ".pem");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(_keyFile, key.ExportPkcs8PrivateKeyPem());
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(_keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    public void Dispose() => File.Delete(_keyFile);
    private SocaProfile Profile() => new() { Name = "staff", Origin = "https://cms.example.com", PrivateKeyFile = _keyFile, ClientName = "Example CMS", AllowDomains = ["example.com"] };
    private static ClaimsPrincipal Principal(string email = "person@example.com", string verified = "true", string type = ClaimValueTypes.Boolean) => new(new ClaimsIdentity([new Claim("sub", "stable-subject"), new Claim("email", email), new Claim("email_verified", verified, type)]));

    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("a.example.com", "example.com", false)]
    [InlineData("a.example.com", "*.example.com", true)]
    [InlineData("a.b.example.com", "*.example.com", true)]
    [InlineData("example.com", "*.example.com", false)]
    [InlineData("badexample.com", "*.example.com", false)]
    public void DomainsMatchDnsLabels(string domain, string rule, bool expected) => Assert.Equal(expected, Admission.DomainMatches(domain, rule));

    [Theory]
    [InlineData("*example.com")]
    [InlineData("a.*.example.com")]
    [InlineData("https://example.com")]
    [InlineData("person@example.com")]
    [InlineData("com")]
    [InlineData("*.com")]
    [InlineData("example..com")]
    [InlineData("example.com.")]
    [InlineData("-bad.example")]
    public void MalformedRulesFailOnSave(string rule) => Assert.Throws<InvalidOperationException>(() => Admission.DomainRule(rule));

    [Fact]
    public void AdmissionDeniesByDefault()
    {
        var profile = Profile(); profile.AllowDomains = [];
        Assert.Throws<InvalidOperationException>(() => Admission.Evaluate(profile, Principal(), DateTimeOffset.UtcNow));
    }
    [Fact]
    public void DenyHasPrecedence()
    {
        var profile = Profile(); profile.DenyDomains = ["example.com"];
        Assert.Throws<InvalidOperationException>(() => Admission.Evaluate(profile, Principal(), DateTimeOffset.UtcNow));
    }
    [Fact]
    public void StringTrueDoesNotProveVerifiedEmail() => Assert.Throws<InvalidOperationException>(() => Admission.Evaluate(Profile(), Principal(type: ClaimValueTypes.String), DateTimeOffset.UtcNow));
    [Fact]
    public void Es256MetadataPublishesOnlyPublicClientData()
    {
        var profile = Profile(); profile.Validate(); var doc = profile.Document();
        Assert.Equal("ES256", doc["token_endpoint_auth_signing_alg"]);
        Assert.Equal("ES256", doc["id_token_signed_response_alg"]);
        Assert.Equal(profile.Origin + profile.MetadataPath, doc["client_id"]);
        Assert.False(profile.PublicJwk().ContainsKey("d"));
        Assert.DoesNotContain("PRIVATE KEY", SocaProfile.Canonical(doc));
    }
    [Fact]
    public void ProxyContainsDeterministicMetadataWithoutClientId()
    {
        var profile = Profile(); profile.MetadataMode = "proxy"; profile.InlineJwks = true;
        profile.PolicyUri = "https://cms.example.com/privacy"; profile.TosUri = "https://cms.example.com/terms";
        profile.Validate(); var encoded = profile.ClientId.Split('/')[^1];
        var decoded = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(encoded));
        using var json = JsonDocument.Parse(decoded);
        Assert.False(json.RootElement.TryGetProperty("client_id", out _));
        Assert.Equal(SocaProfile.Canonical(profile.Metadata()), decoded);
        Assert.Equal("https://cms.example.com/privacy", json.RootElement.GetProperty("policy_uri").GetString());
    }
    [Fact]
    public void ChangingOnlyEnabledKeepsEvidenceRevision()
    {
        var profile = Profile(); var fingerprint = profile.Fingerprint; profile.Enabled = true;
        Assert.Equal(fingerprint, profile.Fingerprint);
        profile.AllowDomains = ["new.example.com"]; Assert.NotEqual(fingerprint, profile.Fingerprint);
    }
    [Theory]
    [InlineData("http://proxy.example/%s")]
    [InlineData("https://%s.proxy.example/cimd")]
    [InlineData("https://%s.proxy.example.com/MARKER")]
    [InlineData("https://proxy.example/cimd?payload=%s")]
    [InlineData("https://proxy.example/%s/%s")]
    public void UnsafeProxyTemplatesRejected(string template)
    {
        var profile = Profile(); profile.MetadataMode = "proxy"; profile.ProxyTemplate = template;
        Assert.Throws<InvalidOperationException>(profile.Validate);
    }
    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.0.0.2", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("192.168.0.1", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("203.0.113.2", false)]
    [InlineData("192.88.99.1", false)]
    [InlineData("2001:20::1", false)]
    [InlineData("3fff::1", false)]
    [InlineData("::1", false)]
    [InlineData("fc00::1", false)]
    [InlineData("::ffff:8.8.8.8", false)]
    [InlineData("8.8.8.8", true)]
    [InlineData("2606:4700:4700::1111", true)]
    public void PrivateAndSpecialNetworkAddressesRejected(string address, bool allowed) => Assert.Equal(allowed, NetworkGuard.PublicAddress(IPAddress.Parse(address)));
    [Fact]
    public void DuplicateJsonMembersRejected()
    {
        using var json = JsonDocument.Parse("{\"issuer\":\"one\",\"issuer\":\"two\"}");
        Assert.Throws<InvalidOperationException>(() => NetworkGuard.RejectDuplicates(json.RootElement));
    }
    [Fact]
    public void NativeHandlerSecuritySettingsArePinned()
    {
        var profile = Profile(); var options = new OpenIdConnectOptions();
        Protocol.Configure(options, profile, new SocaOptions());
        Assert.True(options.UsePkce); Assert.False(options.SaveTokens); Assert.False(options.MapInboundClaims);
        Assert.Equal("code", options.ResponseType); Assert.Equal("query", options.ResponseMode);
        Assert.Equal(["ES256"], options.TokenValidationParameters.ValidAlgorithms);
        Assert.Equal(TimeSpan.FromMinutes(5), options.RemoteAuthenticationTimeout);
        Assert.True(options.ProtocolValidator.RequireNonce);
    }
    [Fact]
    public void NativeBackofficeSchemeMatchesRegistration()
    {
        var profile = Profile(); Assert.Equal(BackOfficeAuthenticationBuilder.SchemeForBackOffice("Soca." + profile.Name), profile.Scheme);
    }
    [Fact]
    public void NativeMemberSchemeMatchesRegistration()
    {
        var profile = Profile(); profile.Surface = "member";
        Assert.Equal(new MemberAuthenticationBuilder(new ServiceCollection()).SchemeForMembers("Soca." + profile.Name), profile.Scheme);
    }
    [Fact]
    public void CandidateEvidenceRequiresTheSameStillAuthenticatedLocalAdministrator()
    {
        var original = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "operator-one"), new Claim(ClaimTypes.Role, "admin")], "native-cookie"));
        var switched = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "operator-two"), new Claim(ClaimTypes.Role, "admin")], "native-cookie"));
        Assert.True(Protocol.OperatorMatches(original, "operator-one"));
        Assert.False(Protocol.OperatorMatches(switched, "operator-one"));
        Assert.False(Protocol.OperatorMatches(null, "operator-one"));
        Assert.False(Protocol.OperatorMatches(new ClaimsPrincipal(new ClaimsIdentity()), "operator-one"));
    }
    [Fact]
    public void NamespacedSubjectChangesAcrossIssuers()
    {
        Assert.NotEqual(SocaProfile.ProviderKey("https://one.example", "subject"), SocaProfile.ProviderKey("https://two.example", "subject"));
    }
}
