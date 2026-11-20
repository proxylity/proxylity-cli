using System.Text;

namespace Proxylity.Cli;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var redirected = Console.IsOutputRedirected;
        var stdout = redirected ? new AsciiWriter(Console.Out) : Console.Out;
        var app = CliApp.CreateDefault(stdout, Console.Error, color: !redirected, progress: !Console.IsErrorRedirected, TerminalWidth(redirected));
        return await app.RunAsync(args, cts.Token).ConfigureAwait(false);
    }

    /// <summary>The console width, or COLUMNS (default 80) when output is redirected or the width is unavailable.</summary>
    private static int TerminalWidth(bool redirected)
    {
        if (!redirected)
        {
            try
            {
                if (Console.WindowWidth > 0)
                {
                    return Console.WindowWidth;
                }
            }
            catch (IOException)
            {
            }
        }

        return int.TryParse(Environment.GetEnvironmentVariable("COLUMNS"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var columns) && columns > 0 ? columns : 80;
    }
}
