#!/usr/bin/env bash
# =============================================================================
# install-tools.sh — Automated installer for Fackel external tool dependencies
# =============================================================================
#
# Installs the CLI binaries that Fackel agents shell out to:
#   Go tools     : subfinder, naabu, nuclei, httpx, katana, gau, dalfox,
#                  cloudbrute, s3scanner, amass, subzy
#   Rust tools   : feroxbuster
#   Python tools : wafw00f, paramspider (pip from git)
#   Python clone : corsy, linkfinder (git clone + wrapper)
#   Ruby tools   : wpscan
#   System pkgs  : nmap, whois
#   Installers   : trufflehog (official install script)
#   Git-clone    : testssl.sh, whatweb
#
# Usage:
#   ./scripts/install-tools.sh            # install everything
#   ./scripts/install-tools.sh --check    # audit only — show what's installed/missing
#   ./scripts/install-tools.sh --minimal  # install only core tools (nmap, naabu, nuclei, httpx, subfinder)
#
# Requirements:
#   - go  ≥ 1.21   (for Go-based tools)
#   - cargo         (for feroxbuster — optional)
#   - pip / pipx    (for Python tools — optional)
#   - gem           (for WPScan/WhatWeb — optional)
#   - git           (for testssl.sh — optional)
#   - sudo          (for system packages — optional)
#
# The script skips tools that are already in $PATH.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' YELLOW='' RED='' CYAN='' BOLD='' RESET=''
fi

ok()   { printf "${GREEN}  ✓${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}  ⚠${RESET} %s\n" "$*"; }
err()  { printf "${RED}  ✗${RESET} %s\n" "$*"; }
info() { printf "${CYAN}  →${RESET} %s\n" "$*"; }
header() { printf "\n${BOLD}%s${RESET}\n" "$*"; }

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
INSTALLED=0
SKIPPED=0
FAILED=0
MISSING_PREREQS=()

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
CHECK_ONLY=false
MINIMAL=false

for arg in "$@"; do
    case "$arg" in
        --check)   CHECK_ONLY=true ;;
        --minimal) MINIMAL=true ;;
        --help|-h)
            echo "Usage: $0 [--check] [--minimal]"
            echo ""
            echo "  --check    Audit only — show installed/missing tools"
            echo "  --minimal  Install only core tools (nmap, naabu, nuclei, httpx, subfinder)"
            echo ""
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Virtualenv guard — pip install --user fails inside a venv
# ---------------------------------------------------------------------------
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    warn "Virtual environment detected ($VIRTUAL_ENV) — deactivating for system installs"
    export PATH="${PATH//$VIRTUAL_ENV\/bin:/}"
    unset VIRTUAL_ENV
fi

# ---------------------------------------------------------------------------
# Prerequisite detection
# ---------------------------------------------------------------------------
HAS_GO=false
HAS_CARGO=false
HAS_PIPX=false
HAS_PIP=false
HAS_GIT=false
HAS_APT=false
HAS_BREW=false
HAS_GEM=false

command -v go    &>/dev/null && HAS_GO=true
command -v cargo &>/dev/null && HAS_CARGO=true
command -v pipx  &>/dev/null && HAS_PIPX=true
command -v pip   &>/dev/null && HAS_PIP=true
command -v git   &>/dev/null && HAS_GIT=true
command -v apt   &>/dev/null && HAS_APT=true
command -v brew  &>/dev/null && HAS_BREW=true
command -v gem   &>/dev/null && HAS_GEM=true

GOBIN="${GOBIN:-${GOPATH:-$HOME/go}/bin}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

has_binary() {
    command -v "$1" &>/dev/null
}

# Install a Go tool.  Accepts: binary_name go_module [alias]
# If alias is provided, a symlink alias → binary_name is created in GOBIN.
install_go_tool() {
    local binary="$1" module="$2" alias="${3:-}"

    # Check if the target name (alias or binary) is already available.
    local check_name="${alias:-$binary}"
    if has_binary "$check_name"; then
        ok "$check_name already installed ($(command -v "$check_name"))"
        (( SKIPPED++ )) || true
        return
    fi

    if $CHECK_ONLY; then
        err "$check_name not found"
        (( FAILED++ )) || true
        return
    fi

    if ! $HAS_GO; then
        err "$check_name — 'go' not in PATH (required for install)"
        MISSING_PREREQS+=("go")
        (( FAILED++ )) || true
        return
    fi

    info "Installing $check_name via go install …"
    if go install "$module" 2>&1; then
        # Create lowercase symlink when needed (e.g. CloudBrute → cloudbrute).
        if [[ -n "$alias" ]] && [[ -f "$GOBIN/$binary" ]] && ! has_binary "$alias"; then
            ln -sf "$GOBIN/$binary" "$GOBIN/$alias"
            ok "$alias installed (symlink → $binary)"
        else
            ok "$check_name installed"
        fi
        (( INSTALLED++ )) || true
    else
        err "$check_name install failed"
        (( FAILED++ )) || true
    fi
}

# Install a system package (apt or brew).
install_system_pkg() {
    local binary="$1" apt_pkg="${2:-$1}" brew_pkg="${3:-$1}"

    if has_binary "$binary"; then
        ok "$binary already installed ($(command -v "$binary"))"
        (( SKIPPED++ )) || true
        return
    fi

    if $CHECK_ONLY; then
        err "$binary not found"
        (( FAILED++ )) || true
        return
    fi

    if $HAS_APT; then
        info "Installing $binary via apt …"
        if sudo apt-get install -y "$apt_pkg" &>/dev/null; then
            ok "$binary installed"
            (( INSTALLED++ )) || true
        else
            err "$binary install failed"
            (( FAILED++ )) || true
        fi
    elif $HAS_BREW; then
        info "Installing $binary via brew …"
        if brew install "$brew_pkg" &>/dev/null; then
            ok "$binary installed"
            (( INSTALLED++ )) || true
        else
            err "$binary install failed"
            (( FAILED++ )) || true
        fi
    else
        err "$binary — no package manager found (need apt or brew)"
        MISSING_PREREQS+=("apt/brew")
        (( FAILED++ )) || true
    fi
}

# Install a Python CLI tool via pipx (preferred) or pip.
install_python_tool() {
    local binary="$1" package="${2:-$1}"

    if has_binary "$binary"; then
        ok "$binary already installed ($(command -v "$binary"))"
        (( SKIPPED++ )) || true
        return
    fi

    if $CHECK_ONLY; then
        err "$binary not found"
        (( FAILED++ )) || true
        return
    fi

    if $HAS_PIPX; then
        info "Installing $binary via pipx …"
        if pipx install "$package" &>/dev/null; then
            ok "$binary installed (pipx)"
            (( INSTALLED++ )) || true
        else
            err "$binary install failed"
            (( FAILED++ )) || true
        fi
    elif $HAS_PIP; then
        info "Installing $binary via pip …"
        if pip install --user "$package" &>/dev/null; then
            ok "$binary installed (pip --user)"
            (( INSTALLED++ )) || true
        else
            err "$binary install failed"
            (( FAILED++ )) || true
        fi
    else
        err "$binary — neither pipx nor pip found"
        MISSING_PREREQS+=("pipx/pip")
        (( FAILED++ )) || true
    fi
}

# Install a Python CLI tool from a git repository via pipx or pip.
install_python_git_tool() {
    local binary="$1" git_url="$2"

    if has_binary "$binary"; then
        ok "$binary already installed ($(command -v "$binary"))"
        (( SKIPPED++ )) || true
        return
    fi

    if $CHECK_ONLY; then
        err "$binary not found"
        (( FAILED++ )) || true
        return
    fi

    if $HAS_PIPX; then
        info "Installing $binary via pipx (git) …"
        if pipx install "git+$git_url" &>/dev/null; then
            ok "$binary installed (pipx)"
            (( INSTALLED++ )) || true
            return
        fi
    fi

    if $HAS_PIP; then
        info "Installing $binary via pip (git) …"
        if pip install --user "git+$git_url" &>/dev/null; then
            ok "$binary installed (pip --user)"
            (( INSTALLED++ )) || true
            return
        fi
    fi

    err "$binary — install from git failed (tried pipx and pip)"
    (( FAILED++ )) || true
}

# Install a Python script tool by cloning its repo and creating a wrapper.
# Used for tools that are not pip-installable (no setup.py / pyproject.toml).
install_python_clone_tool() {
    local binary="$1" git_url="$2" main_script="$3"
    local install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/$binary"
    local symlink_dir="$HOME/.local/bin"

    if has_binary "$binary"; then
        ok "$binary already installed ($(command -v "$binary"))"
        (( SKIPPED++ )) || true
        return
    fi

    if $CHECK_ONLY; then
        err "$binary not found"
        (( FAILED++ )) || true
        return
    fi

    if ! $HAS_GIT; then
        err "$binary — 'git' not in PATH (required for clone install)"
        MISSING_PREREQS+=("git")
        (( FAILED++ )) || true
        return
    fi

    info "Cloning $binary …"
    if [[ -d "$install_dir" ]]; then
        (cd "$install_dir" && git pull --quiet)
    else
        git clone --depth 1 "$git_url" "$install_dir" &>/dev/null
    fi

    # Install Python dependencies if present.
    if [[ -f "$install_dir/requirements.txt" ]]; then
        pip install --user -r "$install_dir/requirements.txt" &>/dev/null || true
    fi

    # Create wrapper script.
    mkdir -p "$symlink_dir"
    cat > "$symlink_dir/$binary" << WRAPPER
#!/usr/bin/env bash
exec python3 "$install_dir/$main_script" "\$@"
WRAPPER
    chmod +x "$symlink_dir/$binary"

    if has_binary "$binary"; then
        ok "$binary installed ($symlink_dir/$binary)"
        (( INSTALLED++ )) || true
    else
        warn "$binary cloned to $install_dir — add $symlink_dir to \$PATH"
        (( INSTALLED++ )) || true
    fi
}

# Install testssl.sh from git into ~/.local/share/testssl and symlink.
install_testssl() {
    local binary="testssl.sh"
    local install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/testssl"
    local symlink_dir="${HOME}/.local/bin"

    if has_binary "$binary"; then
        ok "$binary already installed ($(command -v "$binary"))"
        (( SKIPPED++ )) || true
        return
    fi

    if $CHECK_ONLY; then
        err "$binary not found"
        (( FAILED++ )) || true
        return
    fi

    if ! $HAS_GIT; then
        err "$binary — 'git' not in PATH (required for install)"
        MISSING_PREREQS+=("git")
        (( FAILED++ )) || true
        return
    fi

    info "Cloning testssl.sh …"
    if [[ -d "$install_dir" ]]; then
        (cd "$install_dir" && git pull --quiet)
    else
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$install_dir" &>/dev/null
    fi

    mkdir -p "$symlink_dir"
    ln -sf "$install_dir/testssl.sh" "$symlink_dir/testssl.sh"

    if has_binary "$binary"; then
        ok "$binary installed ($symlink_dir/testssl.sh)"
        (( INSTALLED++ )) || true
    else
        warn "$binary cloned to $install_dir — add $symlink_dir to \$PATH"
        (( INSTALLED++ )) || true
    fi
}

# Install WhatWeb from git (not on RubyGems as a standard gem).
install_whatweb() {
    local binary="whatweb"
    local install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/whatweb"
    local symlink_dir="$HOME/.local/bin"

    if has_binary "$binary"; then
        ok "$binary already installed ($(command -v "$binary"))"
        (( SKIPPED++ )) || true
        return
    fi

    if $CHECK_ONLY; then
        err "$binary not found"
        (( FAILED++ )) || true
        return
    fi

    # Try system package manager first.
    if $HAS_APT; then
        info "Installing $binary via apt …"
        if sudo apt-get install -y whatweb &>/dev/null; then
            ok "$binary installed (apt)"
            (( INSTALLED++ )) || true
            return
        fi
    elif $HAS_BREW; then
        info "Installing $binary via brew …"
        if brew install whatweb &>/dev/null; then
            ok "$binary installed (brew)"
            (( INSTALLED++ )) || true
            return
        fi
    fi

    # Fall back to git clone.
    if ! $HAS_GIT; then
        err "$binary — 'git' not in PATH (required for install)"
        MISSING_PREREQS+=("git")
        (( FAILED++ )) || true
        return
    fi

    info "Cloning WhatWeb …"
    if [[ -d "$install_dir" ]]; then
        (cd "$install_dir" && git pull --quiet)
    else
        git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git "$install_dir" &>/dev/null
    fi

    # Install bundled gem dependencies if Bundler is available.
    if has_binary "bundle" && [[ -f "$install_dir/Gemfile" ]]; then
        (cd "$install_dir" && bundle install --path vendor/bundle --quiet 2>/dev/null) || true
    fi

    mkdir -p "$symlink_dir"
    ln -sf "$install_dir/whatweb" "$symlink_dir/whatweb"

    if has_binary "$binary"; then
        ok "$binary installed ($symlink_dir/whatweb)"
        (( INSTALLED++ )) || true
    else
        warn "$binary cloned to $install_dir — add $symlink_dir to \$PATH"
        (( INSTALLED++ )) || true
    fi
}

# Install TruffleHog via the official install script (go install won't work
# because the go.mod uses replace directives).
install_trufflehog() {
    local binary="trufflehog"
    local install_dir="$HOME/.local/bin"

    if has_binary "$binary"; then
        ok "$binary already installed ($(command -v "$binary"))"
        (( SKIPPED++ )) || true
        return
    fi

    if $CHECK_ONLY; then
        err "$binary not found"
        (( FAILED++ )) || true
        return
    fi

    # Try package manager first.
    if $HAS_BREW; then
        info "Installing $binary via brew …"
        if brew install trufflehog &>/dev/null; then
            ok "$binary installed (brew)"
            (( INSTALLED++ )) || true
            return
        fi
    fi

    # Fall back to the official install script.
    if has_binary "curl"; then
        info "Installing $binary via official install script …"
        mkdir -p "$install_dir"
        if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
                | sh -s -- -b "$install_dir" 2>/dev/null; then
            if has_binary "$binary"; then
                ok "$binary installed ($install_dir/trufflehog)"
                (( INSTALLED++ )) || true
            else
                warn "$binary installed to $install_dir — add it to \$PATH"
                (( INSTALLED++ )) || true
            fi
            return
        fi
    fi

    err "$binary — install failed (need curl or brew)"
    (( FAILED++ )) || true
}

# Install feroxbuster via cargo or package manager.
install_feroxbuster() {
    local binary="feroxbuster"

    if has_binary "$binary"; then
        ok "$binary already installed ($(command -v "$binary"))"
        (( SKIPPED++ )) || true
        return
    fi

    if $CHECK_ONLY; then
        err "$binary not found"
        (( FAILED++ )) || true
        return
    fi

    # Try package manager first (faster, pre-compiled).
    if $HAS_APT; then
        info "Installing $binary via apt …"
        if sudo apt-get install -y feroxbuster &>/dev/null; then
            ok "$binary installed (apt)"
            (( INSTALLED++ )) || true
            return
        fi
    elif $HAS_BREW; then
        info "Installing $binary via brew …"
        if brew install feroxbuster &>/dev/null; then
            ok "$binary installed (brew)"
            (( INSTALLED++ )) || true
            return
        fi
    fi

    # Fall back to cargo.
    if $HAS_CARGO; then
        info "Installing $binary via cargo (this may take a while) …"
        if cargo install feroxbuster 2>&1; then
            ok "$binary installed (cargo)"
            (( INSTALLED++ )) || true
        else
            err "$binary cargo install failed"
            (( FAILED++ )) || true
        fi
    else
        err "$binary — no package manager or cargo found"
        MISSING_PREREQS+=("cargo/apt/brew")
        (( FAILED++ )) || true
    fi
}

# Install a Ruby gem CLI tool.
install_ruby_tool() {
    local binary="$1" gem_name="${2:-$1}"

    if has_binary "$binary"; then
        ok "$binary already installed ($(command -v "$binary"))"
        (( SKIPPED++ )) || true
        return
    fi

    if $CHECK_ONLY; then
        err "$binary not found"
        (( FAILED++ )) || true
        return
    fi

    if $HAS_GEM; then
        info "Installing $binary via gem …"
        if gem install "$gem_name" --no-document 2>&1; then
            ok "$binary installed (gem)"
            (( INSTALLED++ )) || true
        else
            err "$binary gem install failed"
            (( FAILED++ )) || true
        fi
    elif $HAS_APT; then
        info "Installing $binary via apt …"
        if sudo apt-get install -y "$gem_name" &>/dev/null; then
            ok "$binary installed (apt)"
            (( INSTALLED++ )) || true
        else
            err "$binary install failed"
            (( FAILED++ )) || true
        fi
    elif $HAS_BREW; then
        info "Installing $binary via brew …"
        if brew install "$gem_name" &>/dev/null; then
            ok "$binary installed (brew)"
            (( INSTALLED++ )) || true
        else
            err "$binary install failed"
            (( FAILED++ )) || true
        fi
    else
        err "$binary — neither gem, apt, nor brew found"
        MISSING_PREREQS+=("gem/apt/brew")
        (( FAILED++ )) || true
    fi
}

# =============================================================================
# Main
# =============================================================================

if $CHECK_ONLY; then
    header "Fackel Tool Audit"
    echo "  Checking which external binaries are available …"
else
    header "Fackel Tool Installer"
    echo "  Installing external binaries required by Fackel agents."
    echo ""
    echo "  GOBIN: $GOBIN"
    echo "  Mode:  $( $MINIMAL && echo 'minimal (core tools only)' || echo 'full (all tools)' )"
fi

# ---- Prerequisites ----
header "Prerequisites"
$HAS_GO    && ok "go    $(go version 2>/dev/null | awk '{print $3}')"   || warn "go    not found (needed for Go tools)"
$HAS_CARGO && ok "cargo $(cargo --version 2>/dev/null | awk '{print $2}')" || warn "cargo not found (needed for feroxbuster)"
$HAS_PIPX  && ok "pipx  available"                                    || { $HAS_PIP && ok "pip   available (pipx preferred)" || warn "pip/pipx not found (needed for Python tools)"; }
$HAS_GEM   && ok "gem   available"                                    || warn "gem   not found (needed for wpscan, wtweb)"
$HAS_GIT   && ok "git   available"                                    || warn "git   not found (needed for testssl.sh)"

# ---- System packages ----
header "System Packages"
install_system_pkg "nmap"  "nmap"  "nmap"
install_system_pkg "whois" "whois" "whois"

# ---- Go tools (core) ----
header "Go Tools — Core (ProjectDiscovery)"
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "naabu"     "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool "nuclei"    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "katana"    "github.com/projectdiscovery/katana/cmd/katana@latest"

if ! $MINIMAL; then
    # ---- Go tools (extended) ----
    header "Go Tools — Extended"
    install_go_tool "gau"    "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "dalfox" "github.com/hahwul/dalfox/v2@latest"
    install_go_tool "amass"  "github.com/owasp-amass/amass/v4/...@master"
    install_go_tool "subzy"  "github.com/PentestPad/subzy@latest"
    # CloudBrute installs as "CloudBrute" — create lowercase symlink.
    install_go_tool "CloudBrute" "github.com/0xsha/CloudBrute@latest" "cloudbrute"

    # S3Scanner installs as "S3Scanner" — create lowercase symlink.
    install_go_tool "S3Scanner" "github.com/sa7mon/S3Scanner@latest" "s3scanner"

    # ---- Rust tools ----
    header "Rust Tools"
    install_feroxbuster

    # ---- Python tools ----
    header "Python Tools"
    install_python_tool "wafw00f" "wafw00f"
    install_python_git_tool "paramspider" "https://github.com/devanshbatham/ParamSpider.git"
    install_python_clone_tool "linkfinder" "https://github.com/GerbenJavado/LinkFinder.git" "linkfinder.py"
    install_python_clone_tool "corsy" "https://github.com/s0md3v/Corsy.git" "corsy.py"

    # ---- Ruby tools ----
    header "Ruby Tools"
    install_ruby_tool "wpscan" "wpscan"

    # ---- Installer-based tools ----
    header "Installer Tools"
    install_trufflehog

    # ---- Git-clone tools ----
    header "Git Tools"
    install_testssl
    install_whatweb
fi

# =============================================================================
# Summary
# =============================================================================

header "Summary"

TOTAL=$(( INSTALLED + SKIPPED + FAILED ))
echo ""
printf "  ${GREEN}Installed : %d${RESET}\n" "$INSTALLED"
printf "  ${CYAN}Skipped   : %d${RESET} (already present)\n" "$SKIPPED"
if (( FAILED > 0 )); then
    printf "  ${RED}Failed    : %d${RESET}\n" "$FAILED"
else
    printf "  Failed    : 0\n"
fi
printf "  Total     : %d\n" "$TOTAL"

if (( ${#MISSING_PREREQS[@]} > 0 )); then
    # Deduplicate.
    readarray -t UNIQUE_PREREQS < <(printf '%s\n' "${MISSING_PREREQS[@]}" | sort -u)
    echo ""
    warn "Missing prerequisites: ${UNIQUE_PREREQS[*]}"
    echo "  Install them and re-run this script."
fi

echo ""
if $CHECK_ONLY; then
    if (( FAILED > 0 )); then
        info "Run ./scripts/install-tools.sh to install missing tools."
        exit 1
    else
        ok "All tools are installed."
    fi
else
    if (( FAILED > 0 )); then
        warn "Some tools could not be installed. Check output above."
        exit 1
    else
        ok "All tools installed successfully."
    fi
fi

# Remind about PATH.
echo ""
info "Ensure these directories are in your \$PATH:"
echo "    $GOBIN"
echo "    $HOME/.local/bin"
echo "    $HOME/.cargo/bin"
echo ""
