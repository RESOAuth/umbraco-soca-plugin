using NPoco;
using Umbraco.Cms.Core.Packaging;
using Umbraco.Cms.Infrastructure.Migrations;
using Umbraco.Cms.Infrastructure.Scoping;
using Umbraco.Cms.Infrastructure.Persistence.DatabaseAnnotations;

namespace RESOAuth.Soca.Umbraco;

public interface ISocaStore
{
    void Insert(string key, string value, DateTime expires);
    string? Consume(string key);
    bool HasEvidence(string kind, string revision);
    void RecordEvidence(string kind, string revision);
    void Invalidate();
}

[TableName("socaSecurityState")]
[PrimaryKey("Id", AutoIncrement = false)]
[ExplicitColumns]
public sealed class SecurityState
{
    [Column("Id"), PrimaryKeyColumn(AutoIncrement = false), Length(100)]
    public string Id { get; set; } = "";
    [Column("Value"), Length(200)]
    public string Value { get; set; } = "";
    [Column("Expires")]
    public DateTime Expires { get; set; }
}

public sealed class SocaStore(IScopeProvider scopes) : ISocaStore
{
    public void Insert(string key, string value, DateTime expires)
    {
        using var scope = scopes.CreateScope();
        scope.Database.Execute("DELETE FROM socaSecurityState WHERE Expires < @0", DateTime.UtcNow);
        scope.Database.Insert(new SecurityState { Id = key, Value = value, Expires = expires });
        scope.Complete();
    }

    public string? Consume(string key)
    {
        // Independent native scope makes one-use consumption durable on later login failure.
        using var scope = scopes.CreateScope();
        var state = scope.Database.SingleOrDefault<SecurityState>("WHERE Id=@0 AND Expires>@1", key, DateTime.UtcNow);
        if (state is null) return null;
        var count = scope.Database.Execute("DELETE FROM socaSecurityState WHERE Id=@0", key);
        scope.Complete();
        return count == 1 ? state.Value : null;
    }

    public bool HasEvidence(string kind, string revision)
    {
        using var scope = scopes.CreateScope(autoComplete: true);
        return scope.Database.SingleOrDefault<SecurityState>("WHERE Id=@0 AND Expires>@1", "proof:" + kind + ":" + revision, DateTime.UtcNow) is not null;
    }

    public void RecordEvidence(string kind, string revision)
    {
        using var scope = scopes.CreateScope();
        var id = "proof:" + kind + ":" + revision;
        scope.Database.Execute("DELETE FROM socaSecurityState WHERE Id=@0", id);
        scope.Database.Insert(new SecurityState { Id = id, Value = "passed", Expires = DateTime.UtcNow.AddDays(30) });
        scope.Complete();
    }

    public void Invalidate()
    {
        using var scope = scopes.CreateScope();
        scope.Database.Execute("DELETE FROM socaSecurityState WHERE Id LIKE @0", "tx:%");
        scope.Complete();
    }
}

public sealed class SocaMigrationPlan : PackageMigrationPlan
{
    public SocaMigrationPlan() : base("RESOAuth.Soca") { }
    protected override void DefinePlan() => From(string.Empty).To<CreateSecurityState>("soca-security-state-v1");
}

public sealed class CreateSecurityState(IMigrationContext context) : AsyncMigrationBase(context)
{
    protected override Task MigrateAsync()
    {
        if (!TableExists("socaSecurityState")) Create.Table<SecurityState>().Do();
        return Task.CompletedTask;
    }
}
