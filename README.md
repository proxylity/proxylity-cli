# Proxylity CLI

Understand your Proxylity UDP Gateway deployment.

The Proxylity CLI discovers your listeners and destinations, shows how packets
flow to your AWS resources, and helps you diagnose problems, using your existing
AWS credentials. It is read-only and sends nothing to Proxylity.

> **Status:** early development, not considered stable yet.

## Install

Download the archive for your platform from the GitHub Releases page:
`proxylity-<version>-<rid>.zip` (Windows) or `proxylity-<version>-<rid>.tar.gz` (Linux and macOS), where `<rid>` is
one of `win-x64`, `win-arm64`, `linux-x64`, `linux-arm64`, `osx-x64` or `osx-arm64`. Each archive holds the
`proxylity` executable and the license.

Verify the download, then put `proxylity` on your `PATH`:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify proxylity-<version>-<rid>.tar.gz --repo <owner>/<repo>
tar -xzf proxylity-<version>-<rid>.tar.gz   # or unzip the .zip on Windows
```

See [docs/releasing.md](docs/releasing.md) for details. The command name is `proxylity`; an alias may come later.

## Build

Requires the [.NET SDK](https://dotnet.microsoft.com/download) 11.0 or later (see `global.json`).

```bash
dotnet build
dotnet test
dotnet run --project src/Proxylity.Cli -- --version
```

## Usage

```bash
proxylity list                       # listeners and their destinations
proxylity inspect <target>           # configuration in detail
proxylity diagnose <target>          # check the delivery path
proxylity metrics <target> --since 2h
proxylity logs <target>
proxylity check-access               # which read actions your identity can perform
proxylity version                    # same as --version
```

Use `--quiet` to hide the progress line on stderr (errors are still shown).

`-o json` and `-o markdown` change the output format. `inspect -o graph` (also `--format graph`) draws a tree per listener in the terminal: the listener, its destinations and their targets, with the region of each target. Destinations used by more than one listener are marked as shared. It uses ASCII connectors when output is redirected, wraps to the terminal width (`COLUMNS` when redirected), and honors `--no-color`.
Run `proxylity --help` for all options and exit codes.
The identity that runs the CLI needs the read-only AWS permissions listed in [docs/permissions.md](docs/permissions.md).
The facts the CLI relies on are listed in [docs/public-contract.md](docs/public-contract.md).

A **Healthy** finding means Proxylity accepted the packets for delivery and reported no errors. It does not
confirm that packets reached the destination.

### Not in the first release

- SVG graph output. The terminal graph (`inspect -o graph`) and Mermaid diagrams (`-o markdown`) are available.
- `--all-regions` (use `--region`).
- Discovery without a CloudFormation stack.
- Stack-event failure analysis.
- IoT Data and Location tracker destinations (recognized only as ARN services).
- Packet-source subscription check.
- Destination names taken from stack outputs.
- Per-service error-reporting hints.
- Agent Skill.

## Versioning and releases

Releases use [semantic versions](https://semver.org) as plain tags with no prefix (for example `1.2.3`).
Publishing a GitHub Release with such a tag builds, tests and attaches binaries, checksums, an SBOM and attestations.
Use `X.Y.Z` for a stable release and `X.Y.Z-rc.1` (any tag containing `-`) for a prerelease; prerelease tags are marked as such on the GitHub Release.
The maintainer steps are in [docs/releasing.md](docs/releasing.md).

Other builds are prereleases: the patch number of the previous release is incremented and the number of
commits since that release and the commit hash are appended, for example `1.2.4-5+1a2b3c4d`. With no previous release the base is `0.0.0`.
`eng/Get-Version.ps1` computes the version; CI checkouts need full history (`fetch-depth: 0`).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
