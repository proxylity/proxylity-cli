# Contributing

Thanks for your interest in the Proxylity CLI.

## Ground rules

- The CLI is read-only. It must not modify AWS resources.
- It must not send customer data, infrastructure details, or logs to any third party.
- It relies only on publicly documented Proxylity resources, properties, metrics and log formats, plus data in the user's own AWS account. Public facts the CLI depends on are listed in [docs/public-contract.md](docs/public-contract.md).
- Test data and examples must be synthetic. Never include real account IDs, stack names, or log contents.
- Code must stay trimming- and AoT-compatible. The build enables the analyzers; do not suppress warnings without a comment explaining why.
  - Use source-generated `System.Text.Json` contexts only.
  - Avoid runtime reflection and dynamic code generation.

## Development

```bash
dotnet build
dotnet test
```

## Repository checks

Pull requests run a gate that scans for secrets and denied content, checks dependency licenses, and requires
GitHub Actions to be pinned to commit SHAs. You can run most of it locally (PowerShell):

```powershell
./eng/gate/Test-Denylist.ps1
./eng/gate/Test-ActionPins.ps1
dotnet restore; ./eng/gate/Test-Licenses.ps1
```

Allowed dependency licenses are listed in `eng/gate/licenses.allowed.txt`. Add a new dependency only if its
license is on that list.

## Pull requests

- Keep changes focused, with tests where behavior changes.
- Describe what changed and why.
- Do not include secrets or credentials in issues or pull requests. Redact account IDs and log contents from anything you post.

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md), not in public issues.
