using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Umbraco.Cms.Core.Routing;

namespace RESOAuth.Soca.Umbraco;

// Wait for native migrations before invalidating durable pending state. Native local
// authentication remains available without loading any disabled provider signing key.
public sealed class EmergencyStateInvalidator(SocaOptions options, IContentRoutingReadiness readiness, IServiceScopeFactory scopes) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.IsEmergency() && !options.Profiles.Any(profile => profile.EmergencyDisabled)) return;
        while (!readiness.IsReady) await Task.Delay(250, stoppingToken);
        using var scope = scopes.CreateScope();
        scope.ServiceProvider.GetRequiredService<ISocaStore>().Invalidate();
    }
}
