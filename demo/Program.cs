using RESOAuth.Soca.Umbraco;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile("appsettings.example.json", optional: false, reloadOnChange: false);
var extraConfig = Environment.GetEnvironmentVariable("SOCA_CONFIG_FILE");
if (!string.IsNullOrEmpty(extraConfig)) builder.Configuration.AddJsonFile(extraConfig, optional: false, reloadOnChange: false);
var dataDirectory = Path.Combine(builder.Environment.ContentRootPath, "umbraco", "Data");
Directory.CreateDirectory(dataDirectory);
if (builder.Configuration["ConnectionStrings:umbracoDbDSN"]?.StartsWith("Data Source=umbraco/", StringComparison.Ordinal) == true)
    builder.Configuration["ConnectionStrings:umbracoDbDSN"] = "Data Source=" + Path.Combine(dataDirectory, "Umbraco.sqlite.db") + ";Cache=Shared;Foreign Keys=True;Pooling=True";
builder.CreateUmbracoBuilder().AddBackOffice().AddWebsite().AddComposers().AddSoca().Build();
var app = builder.Build();
await app.BootUmbracoAsync();
app.UseUmbraco().WithMiddleware(umbraco => { umbraco.UseBackOffice(); umbraco.UseWebsite(); })
    .WithEndpoints(umbraco => { umbraco.UseBackOfficeEndpoints(); umbraco.UseWebsiteEndpoints(); });
app.MapSoca();
await app.StartAsync();
if (Environment.GetEnvironmentVariable("SOCA_HOST_CHECKS") == "1")
{
    using var scope = app.Services.CreateScope();
    var store = scope.ServiceProvider.GetRequiredService<ISocaStore>();
    var id = "tx:" + Guid.NewGuid().ToString("N");
    store.Insert(id, "host-fixture", DateTime.UtcNow.AddMinutes(1));
    if (store.Consume(id) != "host-fixture" || store.Consume(id) is not null) throw new InvalidOperationException("Native replay consumption failed");
    store.Insert("tx:" + Guid.NewGuid().ToString("N"), "expired-fixture", DateTime.UtcNow.AddMinutes(-1));
    store.Invalidate();
    if (store.HasEvidence("document", "unverified-provider")) throw new InvalidOperationException("Unexpected candidate evidence");
    Console.WriteLine("SOCA_HOST_CHECKS: native replay consumption, replay rejection, invalidation and absent provider evidence passed");
}
await app.WaitForShutdownAsync();
