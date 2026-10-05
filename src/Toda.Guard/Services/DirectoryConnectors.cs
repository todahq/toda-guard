using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Toda.Guard.Directories;
using Toda.Guard.Domain;
using Toda.Platform.Plugins;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>
/// Encrypts secret directory settings (bind passwords) at rest. They have to be reversible because the
/// password is replayed to bind, so they are encrypted rather than hashed, and never returned by the API.
/// </summary>
public class DirectorySecrets(IDataProtectionProvider dataProtection) : ISingletonDependency
{
    private readonly IDataProtector _protector = dataProtection.CreateProtector("Toda.Guard.DirectorySecrets.v1");

    public const string Mask = "********";

    public string? Protect(IReadOnlyDictionary<string, string> secrets) =>
        secrets.Count == 0 ? null : _protector.Protect(JsonSerializer.Serialize(secrets));

    public Dictionary<string, string> Unprotect(string? protectedSecrets) =>
        string.IsNullOrEmpty(protectedSecrets)
            ? new Dictionary<string, string>()
            : JsonSerializer.Deserialize<Dictionary<string, string>>(_protector.Unprotect(protectedSecrets)) ?? new();
}

/// <summary>Finds the connector for a directory type among core and plugin-provided extensions.</summary>
public class ConnectorCatalog(PluginRuntime runtime, IServiceProvider services, DirectorySecrets secrets) : ITransientDependency
{
    public async Task<T> WithConnectorAsync<T>(string type, Func<IDirectoryConnector?, string?, Task<T>> work)
    {
        await using ExtensionLease<IDirectoryConnector> lease = runtime.LeaseExtensions<IDirectoryConnector>(services);
        (string? pluginKey, IDirectoryConnector? connector) = lease.Items.FirstOrDefault(i => i.Instance.Type == type);
        return await work(connector, pluginKey);
    }

    public async Task<List<ConnectorDescription>> DescribeAllAsync()
    {
        await using ExtensionLease<IDirectoryConnector> lease = runtime.LeaseExtensions<IDirectoryConnector>(services);
        return lease.Items
            .Select(i => new ConnectorDescription(i.Instance.Type, i.Instance.DisplayName, i.Instance.Capabilities, i.Instance.Settings.ToList(), i.PluginKey))
            .ToList();
    }

    public DirectoryConnectionContext BuildContext(UserDirectory directory)
    {
        Dictionary<string, string> settings = JsonSerializer.Deserialize<Dictionary<string, string>>(directory.SettingsJson) ?? new();
        foreach ((string name, string value) in secrets.Unprotect(directory.ProtectedSecrets))
        {
            settings[name] = value;
        }

        return new DirectoryConnectionContext(directory.Id, directory.Name, settings);
    }
}

public sealed record ConnectorDescription(
    string Type,
    string DisplayName,
    DirectoryCapabilities Capabilities,
    List<DirectorySettingDefinition> Settings,
    string? PluginKey);
