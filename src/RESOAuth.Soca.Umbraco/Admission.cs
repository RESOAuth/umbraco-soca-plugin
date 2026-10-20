using System.Globalization;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace RESOAuth.Soca.Umbraco;

public static class Admission
{
    public static string DomainRule(string value)
    {
        if (!value.All(char.IsAscii) || value != value.Trim()) throw new InvalidOperationException("Invalid domain rule");
        value = value.ToLowerInvariant();
        var domain = value.StartsWith("*.", StringComparison.Ordinal) ? value[2..] : value;
        var labels = domain.Split('.');
        if (domain.Length > 253 || labels.Length < 2 || labels.Any(label => !Regex.IsMatch(label, "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")) || labels[^1].All(char.IsDigit))
            throw new InvalidOperationException("Domain rules require exact DNS names or one leading *. and a dotted DNS name");
        return value;
    }

    public static string Email(string value)
    {
        if (!value.All(char.IsAscii) || value.Length > 254 || value.Count(x => x == '@') != 1) throw new InvalidOperationException("Invalid verified email");
        var parts = value.Split('@');
        if (!Regex.IsMatch(parts[0], "^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$") || parts[0].StartsWith('.') || parts[0].EndsWith('.') || parts[0].Contains("..") || parts[1].Contains('*'))
            throw new InvalidOperationException("Invalid verified email");
        DomainRule(parts[1]); return value.ToLowerInvariant();
    }

    public static bool DomainMatches(string domain, string rule)
    {
        domain = domain.ToLowerInvariant(); rule = DomainRule(rule);
        return rule.StartsWith("*.", StringComparison.Ordinal) ? domain.EndsWith("." + rule[2..], StringComparison.Ordinal) : domain == rule;
    }

    public static string Evaluate(SocaProfile profile, ClaimsPrincipal principal, DateTimeOffset now)
    {
        var verified = principal.FindAll("email_verified").ToArray();
        // JsonClaimValueTypes.Boolean is preserved by the maintained OIDC handler.
        if (verified.Length != 1 || verified[0].ValueType != ClaimValueTypes.Boolean || !bool.TryParse(verified[0].Value, out var yes) || !yes)
            throw new InvalidOperationException("Verified email is required");
        var emails = principal.FindAll("email").ToArray();
        if (emails.Length != 1) throw new InvalidOperationException("Exactly one verified email is required");
        var email = Email(emails[0].Value); var domain = email.Split('@')[1];
        if (profile.DenyEmails.Any(x => Email(x) == email) || profile.DenyDomains.Any(x => DomainMatches(domain, x)) || !(profile.AllowEmails.Any(x => Email(x) == email) || profile.AllowDomains.Any(x => DomainMatches(domain, x))))
            throw new InvalidOperationException("SOCA admission denied");
        if (profile.MaxAgeSeconds is int maxAge)
        {
            var authTime = principal.FindFirst("auth_time");
            if (authTime is null || !long.TryParse(authTime.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp) || now.ToUnixTimeSeconds() - timestamp < -30 || now.ToUnixTimeSeconds() - timestamp > maxAge + 30)
                throw new InvalidOperationException("Fresh authentication is required");
        }
        if (profile.RequiredAcr.Length != 0 && !profile.RequiredAcr.Contains(principal.FindFirst("acr")?.Value, StringComparer.Ordinal))
            throw new InvalidOperationException("Configured authentication assurance is required");
        var amr = principal.FindAll("amr").Select(x => x.Value).ToArray();
        if (profile.RequiredAmr.Any(x => !amr.Contains(x, StringComparer.Ordinal))) throw new InvalidOperationException("Configured authentication methods are required");
        return email;
    }
}
