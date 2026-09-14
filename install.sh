#!/usr/bin/env bash
# Gatekeeper installer - installs the required scanners on macOS and Linux.
set -u

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

TOOLS=(semgrep trivy gitleaks osv-scanner checkov syft grype nuclei)

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}python3 not found. Install Python 3.9+ first: https://python.org${NC}"
    exit 1
fi

detect_install_backend() {
    if command -v brew >/dev/null 2>&1; then
        echo "brew"
    elif command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    else
        echo "none"
    fi
}

BACKEND=$(detect_install_backend)

if [ "$BACKEND" = "brew" ]; then
    echo "Detected macOS/Homebrew - installing missing scanners via brew."
    missing=()
    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo -e "${GREEN}[ok]${NC} $tool already installed"
        else
            missing+=("$tool")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "Installing: ${missing[*]}"
        brew install "${missing[@]}"
    fi
else
    echo "Detected Linux (package manager: $BACKEND)."
    echo "Homebrew not found. Gatekeeper itself needs no installation, but the"
    echo "scanners do. Recommended install methods:"
    echo
    echo "  - semgrep:      pip3 install semgrep"
    echo "  - trivy:        see https://trivy.dev/latest/getting-started/installation/"
    echo "  - gitleaks:     see https://github.com/gitleaks/gitleaks#installing"
    echo "  - osv-scanner:  see https://google.github.io/osv-scanner/installation/"
    echo "  - checkov:      pip3 install checkov"
    echo "  - syft/grype:   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin"
    echo "                  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin"
    echo "  - nuclei:       go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    echo
    echo "Or install Homebrew for Linux (https://docs.brew.sh/Homebrew-on-Linux)"
    echo "and re-run this script for one-command setup."
    echo
    if [ "$BACKEND" = "apt" ] && command -v zenity >/dev/null 2>&1; then
        :
    elif [ "$BACKEND" = "apt" ]; then
        echo -e "${YELLOW}[info]${NC} For the web UI folder picker on Linux, install a picker:"
        echo "       sudo apt-get install -y zenity   (or python3-tk)"
    fi
fi

if command -v docker >/dev/null 2>&1; then
    echo -e "${GREEN}[ok]${NC} docker found (enables optional ZAP/Nuclei DAST and MobSF mobile scans)"
else
    echo -e "${YELLOW}[warn]${NC} docker not found - optional ZAP/MobSF scans will be skipped"
fi

# Optional: GuardDog (malicious package detection). Requires compiling
# yara-python, which may fail on some toolchains - hence not in TOOLS.
if ! command -v guarddog >/dev/null 2>&1; then
    echo -e "${YELLOW}[info]${NC} guarddog not installed (optional malicious-package scanning)."
    echo "       Try: pip3 install guarddog"
fi

echo
echo "Validating:"
FAILED=0
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "${GREEN}[ok]${NC} $tool $($tool --version 2>/dev/null | head -n 1)"
    else
        echo -e "${RED}[fail]${NC} $tool still missing"
        FAILED=1
    fi
done

echo
if [ "$FAILED" -eq 0 ]; then
    echo "Done. Run a scan with: ./bin/gatekeeper scan /path/to/project"
else
    echo "Some tools are missing. Gatekeeper skips missing tools automatically,"
    echo "but a full scan needs all of them. Install the ones flagged above."
fi
