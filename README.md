<div align="center">

<div>
<img src="assets/aesthetic_banner.jpeg" alt="BugBounty-recon" width="100%">
</div>

<p>
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white" alt="Go 1.25+">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license">
  <img src="https://img.shields.io/badge/platform-Linux-333" alt="Linux">
  <img src="https://img.shields.io/badge/PRs-welcome-2ea043" alt="PRs welcome">
</p>

<strong>A modular bug bounty recon tool.</strong><br>
<sub>Orchestrates best-in-class open-source tools into one dependency-aware pipeline.</sub>
</div>

---

> [!WARNING]
> **Authorized use only.** Run this only against assets you own or are explicitly
> permitted to test (for example, targets within the scope of a bug bounty program
> or a signed engagement). You are responsible for complying with all applicable
> laws and program rules.

The tool contains no scanning logic of its own: every external command goes through
one wrapper, and each stage **warns and continues** when a tool, API key, or input
file is missing rather than aborting the whole run.

## How it works

The pipeline is a set of modules wired together by their **declared dependencies**,
not a fixed order. Each module waits only for the modules it actually depends on, so
independent branches run concurrently.

### Three levels of concurrency

| Level | What runs in parallel |
|:--|:--|
| **Pipeline** | independent branches of the dependency graph run together |
| **Module** | a module's independent steps run together |
| **Command** | each external tool uses its own thread flag |

### Pipeline stages

| Phase | Stages |
|:--|:--|
| **Discover** | passive subdomain enum · active DNS bruteforce + permutation · infra / ASN mapping |
| **Probe** | liveness detection + tech fingerprint · origin-IP discovery · virtual-host enum |
| **Enumerate** | URL / endpoint discovery · JavaScript analysis · directory bruteforce |
| **Intel** | source-code intelligence · port scanning · subdomain-takeover · search-engine dorking |

> [!NOTE]
> A module with **no input** (because an upstream module produced nothing) is
> **skipped, not failed** — and downstream modules keep running.

## Requirements

- **Go 1.25+**
- The external tools the modules call — install what you can with the bundled script
  (below); `./recon-cli doctor` reports what is present or missing.
- *Optional* API keys (GitHub, Shodan, ProjectDiscovery Cloud) enable extra sources;
  without them the matching steps are simply skipped.

## Install

```sh
git clone https://github.com/Qtlas/BugBounty-recon.git
cd BugBounty-recon
go build -o recon-cli ./cmd/recon-cli

./install.sh          # install the external tools (any Linux distro)
./recon-cli doctor    # check which tools are on your PATH
```

`install.sh` uses `go install` for Go-based tools and your system package manager
(apt / dnf / pacman / zypper / apk) for the rest, with build/clone fallbacks.
Anything it cannot install automatically is listed at the end.

## Configure

```sh
cp recon.config.example.yaml recon.config.yaml
# edit recon.config.yaml: domain, wordlists, resolvers, API keys...
```

Relative paths in the config are resolved against the config file's own directory,
so the binary can be launched from anywhere. Every field is documented in
`recon.config.example.yaml`.

## Usage

```sh
# Run a single module (useful for debugging one stage)
./recon-cli run passive --config recon.config.yaml

# Run the full pipeline (or a subset) concurrently, respecting dependencies
./recon-cli scan --config recon.config.yaml
./recon-cli scan --config recon.config.yaml --modules passive,infra

# Inspect progress / stop a running scan / (re)generate the report
./recon-cli status --config recon.config.yaml
./recon-cli quit   --config recon.config.yaml
./recon-cli report --config recon.config.yaml
```

While a `scan` runs you can type `status` or `quit` directly in its terminal, or run
`recon-cli status` / `recon-cli quit` from another shell. Stopping a scan cancels all
in-flight commands cleanly; modules that had not started are marked interrupted.

Outputs are written under the configured `output_dir`: per-stage files, a
`state.json` execution record, and a generated report (`recon.json`,
`functionality_map.json`, `findings.md`).

## MCP server &nbsp;<img src="https://img.shields.io/badge/status-coming%20soon-yellow" alt="coming soon" valign="middle">

An experimental MCP server (`cmd/recon-mcp`) exposes the same modules as MCP tools
over stdio, so the pipeline can be driven from an MCP-capable client. It is still
**work in progress** and not yet considered stable — the CLI is the supported entry
point for now. Feedback and issues are welcome.

## License

MIT — see [LICENSE](LICENSE)

---

<sub>This repository was built with the help of AI.</sub>

