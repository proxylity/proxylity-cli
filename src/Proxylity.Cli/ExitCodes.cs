namespace Proxylity.Cli;

/// <summary>Process exit codes. Stable: scripts and agents depend on them.</summary>
internal static class ExitCodes
{
    /// <summary>The command succeeded and nothing needing attention was found.</summary>
    public const int Success = 0;

    /// <summary>The command succeeded and found one or more problems (used by diagnostic commands).</summary>
    public const int FindingsPresent = 1;

    /// <summary>Invalid arguments, or an ambiguous or unknown target.</summary>
    public const int Usage = 2;

    /// <summary>Credentials, region or authorization prevented the command from running.</summary>
    public const int Access = 3;

    /// <summary>The command ran but could not reach a conclusion.</summary>
    public const int Inconclusive = 4;

    /// <summary>Unexpected internal error.</summary>
    public const int Internal = 5;

    /// <summary>Interrupted by the user (conventional 128 + SIGINT).</summary>
    public const int Cancelled = 130;
}
