#!/usr/bin/env bash
# Installs the external tools the recon pipeline orchestrates.
#
# Works on any Linux distribution: Go-based tools are installed with
# `go install`, system packages through whichever package manager is present
# (apt / dnf / pacman / zypper / apk), and the few tools without a packaged
# release are built or cloned as a fallback. Anything that cannot be installed
# automatically is reported at the end so you can install it by hand.
#
# After running this, use `./recon-cli doctor` to see what is actually on PATH.
#
# Usage: ./install.sh

set -uo pipefail

fail_count=0
missing=()

info() { printf '[*] %s\n' "$1"; }
ok()   { printf '[OK] %s\n' "$1"; }
err()  { printf '[FAIL] %s\n' "$1" >&2; fail_count=$((fail_count + 1)); }

have() { command -v "$1" >/dev/null 2>&1; }

# --- package manager detection ---------------------------------------------
PKG=""
PKG_INSTALL=""
detect_pkg_manager() {
	if   have apt-get; then PKG=apt;    PKG_INSTALL="sudo apt-get install -y"
	elif have dnf;     then PKG=dnf;    PKG_INSTALL="sudo dnf install -y"
	elif have pacman;  then PKG=pacman; PKG_INSTALL="sudo pacman -S --needed --noconfirm"
	elif have zypper;  then PKG=zypper; PKG_INSTALL="sudo zypper install -y"
	elif have apk;     then PKG=apk;    PKG_INSTALL="sudo apk add"
	else info "no supported package manager found; system packages must be installed manually"
	fi
	[ -n "$PKG" ] && info "package manager: $PKG"
}

# sys_install <command> [package-name]
sys_install() {
	local cmd="$1" pkg="${2:-$1}"
	have "$cmd" && { ok "$cmd (already present)"; return; }
	[ -z "$PKG_INSTALL" ] && { missing+=("$cmd"); err "$cmd (no package manager, install manually)"; return; }
	info "installing $cmd via $PKG"
	if $PKG_INSTALL "$pkg" >/dev/null 2>&1; then ok "$cmd"; else missing+=("$cmd"); err "$cmd ($PKG install failed, install manually)"; fi
}

require_go() {
	have go && return
	printf 'Go toolchain is required: https://go.dev/doc/install\n' >&2
	exit 1
}

# go_get <command> <module-path>
go_get() {
	local cmd="$1" pkg="$2"
	have "$cmd" && { ok "$cmd (already present)"; return; }
	info "installing $cmd ($pkg)"
	if go install "$pkg" >/dev/null 2>&1; then ok "$cmd"; else missing+=("$cmd"); err "$cmd (go install failed; run it by hand to see why)"; fi
}

# massdns has no packaged release on most distros: build from source.
install_massdns() {
	have massdns && { ok "massdns (already present)"; return; }
	if have git && have make && have cc; then
		local d; d=$(mktemp -d)
		info "building massdns from source"
		if git clone --depth 1 https://github.com/blechschmidt/massdns.git "$d" >/dev/null 2>&1 && make -C "$d" >/dev/null 2>&1; then
			local bin; bin="$(go env GOPATH)/bin"; mkdir -p "$bin"
			cp "$d/bin/massdns" "$bin/massdns" && ok "massdns (built from source)" || { missing+=(massdns); err "massdns (copy failed)"; }
		else
			missing+=(massdns); err "massdns (build failed, see https://github.com/blechschmidt/massdns)"
		fi
		rm -rf "$d"
	else
		missing+=(massdns); err "massdns (needs git/make/cc to build, install manually)"
	fi
}

# findomain: packaged release binary.
install_findomain() {
	have findomain && { ok "findomain (already present)"; return; }
	if have cargo && cargo install findomain >/dev/null 2>&1; then ok "findomain (cargo)"; return; fi
	missing+=(findomain); err "findomain (install from https://github.com/Findomain/Findomain)"
}

# pip_install <command> [pip-package]  — isolated with pipx when available.
pip_install() {
	local cmd="$1" pkg="${2:-$1}"
	have "$cmd" && { ok "$cmd (already present)"; return; }
	if have pipx && pipx install "$pkg" >/dev/null 2>&1; then ok "$cmd (pipx)"; return; fi
	if have pip3 && pip3 install --user "$pkg" >/dev/null 2>&1; then ok "$cmd (pip --user)"; return; fi
	missing+=("$cmd"); err "$cmd (pipx/pip install failed, install manually)"
}

main() {
	require_go
	detect_pkg_manager
	info "GOPATH/bin: $(go env GOPATH)/bin — make sure it is on your PATH"
	echo

	info "=== passive subdomain enumeration ==="
	go_get subfinder   github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	go_get assetfinder github.com/tomnomnom/assetfinder@latest
	go_get amass       github.com/owasp-amass/amass/v4/cmd/amass@master
	install_findomain

	info "=== active resolution / bruteforce ==="
	install_massdns
	go_get puredns github.com/d3mondev/puredns/v2@latest
	go_get gotator github.com/Josue87/gotator@latest
	go_get ffuf    github.com/ffuf/ffuf/v2@latest

	info "=== infrastructure mapping ==="
	go_get asnmap    github.com/projectdiscovery/asnmap/cmd/asnmap@latest
	go_get mapcidr   github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
	go_get dnsx      github.com/projectdiscovery/dnsx/cmd/dnsx@latest
	go_get metabigor github.com/j3ssie/metabigor@latest

	info "=== liveness and fingerprinting ==="
	go_get httpx      github.com/projectdiscovery/httpx/cmd/httpx@latest
	go_get webanalyze github.com/rverton/webanalyze@latest
	go_get gowitness  github.com/sensepost/gowitness@latest
	sys_install whatweb
	if have webanalyze; then
		dir="${XDG_CONFIG_HOME:-$HOME/.config}/webanalyze"; mkdir -p "$dir"
		( cd "$dir" && webanalyze -update >/dev/null 2>&1 ) \
			&& ok "webanalyze fingerprint database ($dir/technologies.json)" \
			|| err "webanalyze -update failed (run it by hand in $dir)"
	fi

	info "=== content and endpoint discovery ==="
	go_get waybackurls github.com/tomnomnom/waybackurls@latest
	go_get gau         github.com/lc/gau/v2/cmd/gau@latest
	go_get katana      github.com/projectdiscovery/katana/cmd/katana@latest
	pip_install waymore
	pip_install dirsearch

	info "=== JS / secret analysis ==="
	go_get subjs      github.com/lc/subjs@latest
	go_get jsleak     github.com/channyein1990/jsleak@latest
	go_get trufflehog github.com/trufflesecurity/trufflehog/v3@latest

	info "=== source intelligence ==="
	go_get gitleaks github.com/gitleaks/gitleaks/v8@latest
	pip_install metafinder

	info "=== port scanning ==="
	go_get naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	sys_install nmap

	info "=== subdomain takeover ==="
	go_get subzy github.com/PentestPad/subzy@latest

	echo
	if [ "$fail_count" -eq 0 ]; then
		info "all dependencies installed. Run ./recon-cli doctor to verify."
	else
		info "$fail_count tool(s) could not be installed automatically:"
		printf '      %s\n' "${missing[@]}"
		info "install them manually, then run ./recon-cli doctor."
	fi
	echo
	info "Optional helper scripts (set their path in recon.config.yaml under tool_paths):"
	info "  favup, hosthunter, lazyegg — clone from their upstream repos and point tool_paths.<name> at the script."
}

main "$@"
