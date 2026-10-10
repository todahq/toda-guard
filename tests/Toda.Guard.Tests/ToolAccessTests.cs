using System.Text.Json.Nodes;
using Toda.Guard.Services;
using Toda.Platform.Tools;
using Toda.Sdk;

namespace Toda.Guard.Tests;

/// <summary>Who may use a tool (M7): a read-only caller reaches only tools that read; a tool with no requirement is anyone's.</summary>
public class ToolAccessTests
{
    private static ToolInfo Tool(ToolHints hints) => new("t", "t", null, "T", "A tool.", [], null, hints, Requires: null);

    [Fact]
    public async Task A_read_only_caller_reaches_only_tools_that_read()
    {
        GuardToolAccess access = new(abilities: null!); // no requirement: the ability isn't asked
        ToolContext reader = new(Guid.NewGuid(), ReadOnly: true, "mcp");

        Assert.False(await access.AllowsAsync(Tool(ToolHints.Writes), reader, CancellationToken.None));
        Assert.True(await access.AllowsAsync(Tool(ToolHints.Reads), reader, CancellationToken.None));
        Assert.True(await access.AllowsAsync(Tool(ToolHints.Writes), reader with { ReadOnly = false }, CancellationToken.None));
    }
}
