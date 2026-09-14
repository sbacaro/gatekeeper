## Summary

<!-- 1-3 bullets describing the change and why it is needed -->

## Changes

-

## Test plan

- [ ] `./bin/gatekeeper scan ./sample-vulnerable-app` runs and exits as expected
- [ ] `python -m compileall -q gatekeeper/` passes
- [ ] `ruff check gatekeeper/ bin/` passes (if lint config applies)
