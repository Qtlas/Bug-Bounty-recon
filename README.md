# BugBounty-recon

A modular reconnaissance pipeline for authorized security testing, written in
Go. It orchestrates well-known open-source tools (subfinder, httpx, puredns,
naabu, nmap, and others) into a single dependency-aware pipeline and
aggregates their output into structured reports.

The tool contains no scanning logic of its own: every external command goes
through one wrapper, and each stage warns and continues when a tool, API key,
or input file is missing rather than aborting the whole run.

> **Authorized use only.** Run this only against assets you own or are
> explicitly permitted to test (for example, targets within the scope of a
> bug bounty program or a signed engagement). You are responsible for
> complying with all applicable laws and program rules.

## How it works

The pipeline is a set of modules wired together by their declared
dependencies, not a fixed order. Independent branches run concurrently;
each module waits only for the modules it actually depends on. Concurrency
happens at three levels: across pipeline branches, within a module (its
independent steps), and inside each external command (its own thread flag).

Stages include passive subdomain enumeration, active DNS bruteforce and
permutation, infrastructure/ASN mapping, liveness detection and technology
fingerprinting, origin-IP discovery, virtual-host enumeration, URL and
endpoint discovery, JavaScript analysis, directory bruteforce, source-code
intelligence, port scanning, subdomain-takeover checks, and search-engine
dorking. A module with no input (because an upstream module produced nothing)
is skipped, not failed, and downstream modules keep running.

## Requirements

- Go 1.25 or newer.
- The external tools the modules call. Install what you can with the bundled
  script (see below); `./recon-cli doctor` reports what is present or missing.
- Optional API keys (GitHub, Shodan, ProjectDiscovery Cloud) enable extra
  sources; without them the corresponding steps are skipped.

## Install

```sh
git clone https://github.com/Qtlas/BugBounty-recon.git
cd BugBounty-recon
go build -o recon-cli ./cmd/recon-cli

./install.sh          # install the external tools (any Linux distro)
./recon-cli doctor    # check which tools are on your PATH
```

`install.sh` uses `go install` for Go-based tools and your system package
manager (apt / dnf / pacman / zypper / apk) for the rest, with build/clone
fallbacks. Anything it cannot install automatically is listed at the end.

## Configure

```sh
cp recon.config.example.yaml recon.config.yaml
# edit recon.config.yaml: domain, wordlists, resolvers, API keys...
```

Relative paths in the config are resolved against the config file's own
directory, so the binary can be launched from anywhere. See the comments in
`recon.config.example.yaml` for every field.

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

While a `scan` runs you can type `status` or `quit` directly in its terminal,
or run `recon-cli status` / `recon-cli quit` from another shell. Stopping a
scan cancels all in-flight commands cleanly; modules that had not started are
marked interrupted.

Outputs are written under the configured `output_dir`: per-stage files, a
`state.json` execution record, and a generated report (`recon.json`,
`functionality_map.json`, `findings.md`).

## MCP server (coming soon)

An experimental MCP server (`cmd/recon-mcp`) exposes the same modules as MCP
tools over stdio, so the pipeline can be driven from an MCP-capable client. It
is still **work in progress** and not yet considered stable — the CLI is the
supported entry point for now. Feedback and issues are welcome.

## License

MIT — see [LICENSE](LICENSE).
