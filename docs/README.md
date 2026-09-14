# Documentation

- [README](../README.md) - overview, install and usage.
- [Contributing guide](../CONTRIBUTING.md) - dev setup and conventions.
- [Security policy](../SECURITY.md) - how to report vulnerabilities.

## Adding a new scanner

1. Create a runner function in `gatekeeper/scanners/scanners.py` that:
   - runs the tool via `_run()`,
   - writes raw JSON into `raw_dir`,
   - returns `(list[Finding], note)`.
2. Register it in `TOOL_RUNNERS`.
3. Map it to relevant stacks in `gatekeeper/core/runner.py::STACK_TOOL_MAP`.
4. Add it to the scanner table in the README and to `install.sh` if brew-able.
5. Test with `./bin/gatekeeper scan ./sample-vulnerable-app --tools <tool>`.
