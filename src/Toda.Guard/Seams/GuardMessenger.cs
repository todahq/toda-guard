namespace Toda.Guard;

/// <summary>
/// A way that reaches a person (ADR 0087): <c>email</c> to the address their mail goes to, or a channel (sms, whatsapp…)
/// to their verified address on it. <paramref name="Name"/> is the channel's name as people see it.
/// </summary>
public sealed record GuardChannel(string Method, string Name, string Address);

/// <summary>
/// A message Guard sends (ADR 0087): one of its kinds (<see cref="GuardMessageKinds"/>) to an account (by its id) or an
/// address, with the values its template uses. <paramref name="Channel"/> is null for email. A secret one is delivered
/// once as rendered, its text and subject kept nowhere, and never retried; every kind that carries a link or a code
/// (<see cref="GuardMessageKinds.CarriesSecret"/>) is one, whatever the sender says, so no host can forget it.
/// </summary>
public sealed record GuardMessage(
    string Kind,
    Guid? AccountId,
    string? Address,
    string? Name,
    IReadOnlyDictionary<string, object?> Model,
    string? Language,
    string Source,
    string? Channel = null,
    bool Secret = false)
{
    public bool Secret { get; init; } = Secret || GuardMessageKinds.CarriesSecret(Kind);
}

/// <summary>How a message went: how many were sent, and how many recipients nothing reached.</summary>
public sealed record GuardSendResult(int Sent, int Unreachable);

/// <summary>
/// How Guard reaches people (ADR 0087): the mails self-service sends, an added address's confirmation, and a second
/// step's code. The default writes each message, rendered from Guard's own texts, to a pickup folder (Development);
/// a host sends them its own way (Toda: its templates, which admins may reword, and its channels).
/// </summary>
public interface IGuardMessenger
{
    /// <summary>
    /// The ways that reach the person now, in no particular order: email when mail can go out and they have an address,
    /// and each channel where they have a verified address. Guard applies the site's allowed methods itself.
    /// </summary>
    Task<IReadOnlyList<GuardChannel>> ReachAsync(Guid accountId, string? emailAddress, CancellationToken cancellationToken);

    Task<GuardSendResult> SendAsync(GuardMessage message, CancellationToken cancellationToken);
}
