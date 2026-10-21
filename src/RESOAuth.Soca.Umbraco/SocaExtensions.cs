using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Umbraco.Cms.Core.DependencyInjection;
using Umbraco.Cms.Api.Management.Security;
using Umbraco.Cms.Web.Common.Security;
using Umbraco.Extensions;

namespace RESOAuth.Soca.Umbraco;

public static class SocaExtensions
{
    public static IUmbracoBuilder AddSoca(this IUmbracoBuilder builder, Action<SocaOptions>? configure = null)
    {
        var options = new SocaOptions();
        builder.Config.GetSection("Soca").Bind(options);
        configure?.Invoke(options);
        // All settings are deployment-managed. The native GUI exposes effective read-only values.
        options.Prepare(builder.Config["ApplicationName"] ?? System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name ?? "Umbraco");
        builder.PackageMigrationPlans().Add<SocaMigrationPlan>();
        builder.Services.AddAntiforgery();
        builder.Services.AddSingleton(options);
        builder.Services.TryAddScoped<ISocaStore, SocaStore>();
        builder.Services.AddHostedService<EmergencyStateInvalidator>();
        foreach (var profile in options.Profiles.Where(profile => !options.IsEmergency(profile)))
        {
            if (profile.Surface == "backoffice")
                builder.AddBackOfficeExternalLogins(logins => logins.AddBackOfficeLogin(
                    auth => auth.AddOpenIdConnect(BackOfficeAuthenticationBuilder.SchemeForBackOffice("Soca." + profile.Name)!, profile.ClientName, oidc => Protocol.Configure(oidc, profile, options)),
                    provider => { provider.AutoLinkOptions = new ExternalSignInAutoLinkOptions(autoLinkExternalAccount: false); provider.DenyLocalLogin = false; }));
            else
                builder.AddMemberExternalLogins(logins => logins.AddMemberLogin(
                    auth => auth.AddOpenIdConnect(auth.SchemeForMembers("Soca." + profile.Name), profile.ClientName, oidc => Protocol.Configure(oidc, profile, options)),
                    provider => provider.AutoLinkOptions = new MemberExternalSignInAutoLinkOptions(autoLinkExternalAccount: false)));
        }
        return builder;
    }

    public static IEndpointRouteBuilder MapSoca(this IEndpointRouteBuilder endpoints)
    {
        var options = endpoints.ServiceProvider.GetRequiredService<SocaOptions>();
        foreach (var profile in options.Profiles.Where(profile => !options.IsEmergency(profile)))
        {
            endpoints.MapGet(profile.MetadataPath, (HttpContext context) =>
            {
                context.Response.Headers.CacheControl = "public, max-age=60";
                context.Response.Headers.XContentTypeOptions = "nosniff";
                return Results.Json(profile.Document());
            }).AllowAnonymous();
            endpoints.MapGet(profile.JwksPath, (HttpContext context) =>
            {
                context.Response.Headers.CacheControl = "public, max-age=60";
                context.Response.Headers.XContentTypeOptions = "nosniff";
                return Results.Json(new { keys = new[] { profile.PublicJwk() } });
            }).AllowAnonymous();
        }
        return endpoints;
    }
}
