using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;

namespace Toda.Guard.Tests;

/// <summary>Guard's start-up check that the host keeps its Data Protection key ring somewhere it chose (ADR 0082, 0087).</summary>
public class GuardKeyRingTests
{
    [Fact]
    public void A_ring_the_host_keeps_passes_and_one_it_left_to_the_fallback_doesnt()
    {
        string folder = Path.Combine(Path.GetTempPath(), "guard-keys-" + Guid.NewGuid().ToString("N"));

        Assert.Null(GuardKeyRing.Problem(new KeyManagementOptions { XmlRepository = new Database() }));
        Assert.Null(GuardKeyRing.Problem(new KeyManagementOptions { XmlRepository = new FileSystemXmlRepository(new DirectoryInfo(folder), Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance) }));
        Assert.Contains("nowhere it chose", GuardKeyRing.Problem(new KeyManagementOptions()));
        if (FileSystemXmlRepository.DefaultKeyStorageDirectory is { } fallback)
        {
            Assert.Contains("fallback folder", GuardKeyRing.Problem(new KeyManagementOptions { XmlRepository = new FileSystemXmlRepository(fallback, Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance) }));
        }
    }

    /// <summary>A ring kept somewhere the host chose, as Toda's in Postgres.</summary>
    private sealed class Database : IXmlRepository
    {
        public IReadOnlyCollection<XElement> GetAllElements() => [];

        public void StoreElement(XElement element, string friendlyName)
        {
        }
    }
}
