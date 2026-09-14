#!/usr/bin/env bash
# Gatekeeper installer - installs required scanners via Homebrew.
set -u

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

TOOLS=(semgrep trivy gitleaks osv-scanner checkov syft grype nuclei)

if ! command -v brew >/dev/null 2>&1; then
    echo -e "${RED}Homebrew not found. Install it from https://brew.sh first.${NC}"
    exit 1
fi

missing=()
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "${GREEN}[ok]${NC} $tool already installed ($($tool --version 2>/dev/null | head -n 1))"
    else
        missing+=("$tool")
    fi
done

if [ "${#missing[@]}" -gt 0 ]; then
    echo "Installing: ${missing[*]}"
    brew install "${missing[@]}"
fi

if command -v docker >/dev/null 2>&1; then
    echo -e "${GREEN}[ok]${NC} docker found (enables optional ZAP/Nuclei DAST and MobSF mobile scans)"
else
    echo -e "${YELLOW}[warn]${NC} docker not found - optional ZAP/MobSF scans will be skipped"
fi

# Optional: GuardDog (malicious package detection). Requires compiling
# yara-python, which may fail on very new macOS SDKs - hence not in TOOLS.
if ! command -v guarddog >/dev/null 2>&1; then
    echo -e "${YELLOW}[info]${NC} guarddog not installed (optional malicious-package scanning)."
    echo "       Try: pip3 install --break-system-packages guarddog"
fi

echo
echo "Validating:"
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "${GREEN}[ok]${NC} $tool $($tool --version 2>/dev/null | head -n 1)"
    else
        echo -e "${RED}[fail]${NC} $tool still missing"
    fi
done

echo
echo "Done. Run a scan with: ./gatekeeper scan /path/to/project"
