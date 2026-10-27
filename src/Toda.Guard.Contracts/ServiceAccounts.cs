namespace Toda.Guard;

/// <summary>
/// A service account to make: its username, and optionally its display name and whether an automated actor works
/// through it (an agent's account). Members are added by name, so hosts keep building it as fields are added.
/// </summary>
public sealed record ServiceAccountInput(string Username)
{
    public string? DisplayName { get; init; }

    /// <summary>An agent's account: a service account an automated actor works through, which holds no tokens.</summary>
    public bool Agent { get; init; }
}

/// <summary>
/// Service accounts the host makes without going through HTTP. Each has no password and no address, so it can't sign in
/// and no reset or mail reaches it.
/// </summary>
public interface IServiceAccounts
{
    /// <summary>
    /// Makes the account, audited as an account created by whoever the host acts for. Refused when the username isn't
    /// one or is taken.
    /// </summary>
    Task<AccountInfo> CreateAsync(ServiceAccountInput input, CancellationToken cancellationToken = default);
}
