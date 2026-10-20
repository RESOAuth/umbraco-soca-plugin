using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;

namespace RESOAuth.Soca.Umbraco;

public sealed class SocaProfile
{
    public string Name { get; set; } = "soca";
    public string Surface { get; set; } = "backoffice";
    public string Issuer { get; set; } = "https://auth.resoauth.cloud";
    public string Origin { get; set; } = "";
    public string ClientName { get; set; } = "";
    public string? ClientUri { get; set; }
    public string? LogoUri { get; set; }
    public string? PolicyUri { get; set; }
    public string? TosUri { get; set; }
    public string PrivateKeyFile { get; set; } = "";
    public string MetadataMode { get; set; } = "hosted";
    public bool InlineJwks { get; set; }
    public string ProxyTemplate { get; set; } = "https://dynamic-cimd.resoauth.cloud/cimd/%s";
    public string[] AllowEmails { get; set; } = [];
    public string[] DenyEmails { get; set; } = [];
    public string[] AllowDomains { get; set; } = [];
    public string[] DenyDomains { get; set; } = [];
    public bool Enabled { get; set; }
    public bool EmergencyDisabled { get; set; }
    public int? MaxAgeSeconds { get; set; }
    public string[] RequiredAcr { get; set; } = [];
    public string[] RequiredAmr { get; set; } = [];
    public bool ProvisionMembers { get; set; }
    public string MemberTypeAlias { get; set; } = "Member";
    public string? MemberGroup { get; set; }

    public string CallbackPath => $"/umbraco/soca/{Name}/{Surface}/callback";
    public string MetadataPath => $"/soca/{Name}/{Surface}/metadata";
    public string JwksPath => $"/soca/{Name}/{Surface}/jwks";
    public string Callback => Origin.TrimEnd('/') + CallbackPath;
    public string Scheme => Surface == "backoffice" ? "Umbraco.Soca." + Name : "UmbracoMembers.Soca." + Name;

    public void Validate()
    {
        if (!Regex.IsMatch(Name, "^[a-z][a-z0-9_-]{0,39}$") || Surface is not ("backoffice" or "member"))
            throw new InvalidOperationException("SOCA profile name or protected surface invalid");
        NetworkGuard.ValidateUrl(Issuer);
        var origin = NetworkGuard.ValidateUrl(Origin);
        if (origin.AbsolutePath != "/" || origin.Query.Length != 0 || new Uri(Issuer).Query.Length != 0)
            throw new InvalidOperationException("SOCA canonical origin must contain only an HTTPS origin");
        if (ClientName.Length is < 1 or > 200 || MaxAgeSeconds is < 0 or > 86400)
            throw new InvalidOperationException("SOCA application name or max_age invalid");
        foreach (var url in new[] { ClientUri, LogoUri, PolicyUri, TosUri }.Where(x => !string.IsNullOrEmpty(x)))
            NetworkGuard.ValidateUrl(url!);
        foreach (var rule in AllowDomains.Concat(DenyDomains)) Admission.DomainRule(rule);
        foreach (var email in AllowEmails.Concat(DenyEmails)) Admission.Email(email);
        if (MetadataMode is not ("hosted" or "proxy")) throw new InvalidOperationException("Invalid metadata mode");
        if (MetadataMode == "proxy")
        {
            if (ProxyTemplate.Split("%s").Length != 2) throw new InvalidOperationException("Proxy requires exactly one %s");
            var proxy = NetworkGuard.ValidateUrl(ProxyTemplate.Replace("%s", "e30"));
            var shape = Regex.Match(ProxyTemplate, @"^https://[^/?#]+(?<path>/[^?#]*)?(?:\?[^#]*)?$", RegexOptions.CultureInvariant);
            if (!shape.Success || !shape.Groups["path"].Value.Contains("%s", StringComparison.Ordinal) || proxy.Query.Length != 0)
                throw new InvalidOperationException("Proxy placeholder must be in the HTTPS path");
        }
        using var key = SigningKey();
        _ = Document();
        if (ProvisionMembers) throw new InvalidOperationException("Automatic provisioning is not implemented in this alpha; approve a native external association");
    }

    public ECDsa SigningKey()
    {
        if (!Path.IsPathFullyQualified(PrivateKeyFile) || new FileInfo(PrivateKeyFile).Length > 32768)
            throw new InvalidOperationException("SOCA signing key requires a bounded absolute deployment file");
        if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(PrivateKeyFile) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            throw new InvalidOperationException("SOCA private key file requires owner-only permissions");
        var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(PrivateKeyFile));
        if (key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
        { key.Dispose(); throw new InvalidOperationException("SOCA requires an ES256/P-256 signing key"); }
        return key;
    }

    public SortedDictionary<string, object> PublicJwk()
    {
        using var key = SigningKey();
        var p = key.ExportParameters(false);
        var result = new SortedDictionary<string, object>(StringComparer.Ordinal)
        {
            ["kty"] = "EC", ["crv"] = "P-256", ["x"] = WebEncoders.Base64UrlEncode(p.Q.X!),
            ["y"] = WebEncoders.Base64UrlEncode(p.Q.Y!), ["use"] = "sig", ["alg"] = "ES256"
        };
        result["kid"] = Hash(Canonical(result));
        return result;
    }

    public SortedDictionary<string, object> Metadata()
    {
        var value = new SortedDictionary<string, object>(StringComparer.Ordinal)
        {
            ["client_name"] = ClientName, ["client_uri"] = ClientUri ?? Origin.TrimEnd('/') + "/",
            ["redirect_uris"] = new[] { Callback }, ["grant_types"] = new[] { "authorization_code" },
            ["response_types"] = new[] { "code" }, ["scope"] = "openid email", ["application_type"] = "web",
            ["token_endpoint_auth_method"] = "private_key_jwt", ["token_endpoint_auth_signing_alg"] = "ES256",
            ["id_token_signed_response_alg"] = "ES256"
        };
        if (LogoUri is not null) value["logo_uri"] = LogoUri;
        if (PolicyUri is not null) value["policy_uri"] = PolicyUri;
        if (TosUri is not null) value["tos_uri"] = TosUri;
        if (InlineJwks) value["jwks"] = new SortedDictionary<string, object> { ["keys"] = new[] { PublicJwk() } };
        else value["jwks_uri"] = Origin.TrimEnd('/') + JwksPath;
        if (Encoding.UTF8.GetByteCount(Canonical(value)) > 4096) throw new InvalidOperationException("CIMD payload exceeds 4096 bytes");
        return value;
    }

    public string ClientId
    {
        get
        {
            var id = MetadataMode == "hosted" ? Origin.TrimEnd('/') + MetadataPath : ProxyTemplate.Replace("%s", WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(Canonical(Metadata()))));
            if (id.Length > 8192) throw new InvalidOperationException("CIMD URL exceeds 8192 characters");
            return id;
        }
    }

    public SortedDictionary<string, object> Document()
    {
        var value = Metadata(); value["client_id"] = ClientId; return value;
    }

    public string Fingerprint => Hash(Canonical(new SortedDictionary<string, object?>
    {
        ["issuer"] = Issuer, ["document"] = Document(), ["surface"] = Surface,
        ["allow_emails"] = AllowEmails, ["deny_emails"] = DenyEmails,
        ["allow_domains"] = AllowDomains, ["deny_domains"] = DenyDomains,
        ["max_age"] = MaxAgeSeconds, ["acr"] = RequiredAcr, ["amr"] = RequiredAmr,
        ["provision"] = ProvisionMembers, ["member_type"] = MemberTypeAlias, ["member_group"] = MemberGroup
    }));
    public static string Canonical<T>(T value) => JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = false });
    public static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public static string ProviderKey(string issuer, string subject) => Hash(issuer + "\0" + subject);
}

public sealed class SocaOptions
{
    public bool EmergencyDisabled { get; set; }
    public List<SocaProfile> Profiles { get; set; } = [];
}
