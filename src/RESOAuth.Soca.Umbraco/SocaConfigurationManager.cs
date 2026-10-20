using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace RESOAuth.Soca.Umbraco;

/// <summary>Fetch fresh, bounded and duplicate-free issuer trust for each native handler request.</summary>
public sealed class SocaConfigurationManager(SocaProfile profile, HttpClient client) : IConfigurationManager<OpenIdConnectConfiguration>
{
    public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
    {
        var configuration = await OpenIdConnectConfigurationRetriever.GetAsync(
            profile.Issuer.TrimEnd('/') + "/.well-known/openid-configuration", new StrictRetriever(client), cancel);
        Protocol.ValidateDiscovery(profile, configuration);
        return configuration;
    }

    // No cached or last-known-good trust exists in this alpha.
    public void RequestRefresh() { }

    private sealed class StrictRetriever(HttpClient client) : IDocumentRetriever
    {
        public async Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            using var document = await NetworkGuard.Json(client, address, cancel);
            return document.RootElement.GetRawText();
        }
    }
}
