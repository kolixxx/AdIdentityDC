using AdIdentity.Agent.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AdIdentity.Agent.Tests;

/// <summary>
/// [D23 login-memory] Covers the store itself. Delete with the feature.
/// </summary>
public sealed class LoginMemoryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "adidentity-tests", Guid.NewGuid().ToString("n"));

    private string Path_ => Path.Combine(_dir, "login-memory.json");

    private LoginMemory NewMemory() => new(NullLogger<LoginMemory>.Instance, Path_);

    [Fact]
    public void Recalls_the_exact_pair_it_remembered()
    {
        var memory = NewMemory();
        memory.Remember("ivanov", "INTERNAL", "10.0.1.10", DateTimeOffset.UtcNow);

        Assert.True(memory.Recall("ivanov", "INTERNAL", "10.0.1.10", 24));
    }

    [Fact]
    public void Does_not_recall_a_different_address()
    {
        var memory = NewMemory();
        memory.Remember("ivanov", "INTERNAL", "10.0.1.10", DateTimeOffset.UtcNow);

        Assert.False(memory.Recall("ivanov", "INTERNAL", "10.0.1.50", 24));
    }

    [Fact]
    public void Does_not_recall_an_unknown_user()
    {
        var memory = NewMemory();
        memory.Remember("ivanov", "INTERNAL", "10.0.1.10", DateTimeOffset.UtcNow);

        Assert.False(memory.Recall("petrov", "INTERNAL", "10.0.1.10", 24));
    }

    [Fact]
    public void Forgets_a_logon_older_than_the_retention_window()
    {
        var memory = NewMemory();
        memory.Remember("ivanov", "INTERNAL", "10.0.1.10", DateTimeOffset.UtcNow.AddHours(-25));

        Assert.False(memory.Recall("ivanov", "INTERNAL", "10.0.1.10", 24));
    }

    [Fact]
    public void Zero_retention_disables_the_memory()
    {
        var memory = NewMemory();
        memory.Remember("ivanov", "INTERNAL", "10.0.1.10", DateTimeOffset.UtcNow);

        Assert.False(memory.Recall("ivanov", "INTERNAL", "10.0.1.10", 0));
    }

    [Fact]
    public void Survives_a_service_restart()
    {
        NewMemory().Remember("ivanov", "INTERNAL", "10.0.1.10", DateTimeOffset.UtcNow);

        // Fresh instance over the same file, as after a service restart.
        Assert.True(NewMemory().Recall("ivanov", "INTERNAL", "10.0.1.10", 24));
    }

    [Fact]
    public void Keeps_only_the_latest_address_of_a_user()
    {
        var memory = NewMemory();
        memory.Remember("ivanov", "INTERNAL", "10.0.1.10", DateTimeOffset.UtcNow.AddMinutes(-10));
        memory.Remember("ivanov", "INTERNAL", "10.0.1.11", DateTimeOffset.UtcNow);

        Assert.True(memory.Recall("ivanov", "INTERNAL", "10.0.1.11", 24));
        Assert.False(memory.Recall("ivanov", "INTERNAL", "10.0.1.10", 24));
    }

    [Fact]
    public void Ignores_an_empty_address()
    {
        var memory = NewMemory();
        memory.Remember("ivanov", "INTERNAL", "", DateTimeOffset.UtcNow);

        Assert.False(memory.Recall("ivanov", "INTERNAL", "", 24));
    }

    [Fact]
    public void Starts_empty_when_the_file_is_corrupt()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path_, "{ this is not json");

        var memory = NewMemory();

        Assert.False(memory.Recall("ivanov", "INTERNAL", "10.0.1.10", 24));
        memory.Remember("ivanov", "INTERNAL", "10.0.1.10", DateTimeOffset.UtcNow);
        Assert.True(memory.Recall("ivanov", "INTERNAL", "10.0.1.10", 24));
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }
}
