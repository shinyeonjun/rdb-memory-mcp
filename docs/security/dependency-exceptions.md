# Dependency Security Exceptions

## Active exception

| Advisory | Dependency path | Runtime exposure | Decision | Review trigger |
|---|---|---|---|---|
| `RUSTSEC-2024-0436` (`paste` 1.0.15 unmaintained) | `database-memory-core -> oracle 0.6.3 -> paste` | Build-time procedural macro only; no known vulnerability is reported by RustSec. | Temporarily accepted because `oracle` 0.6.3 is the current upstream release and removing it would remove the certified Oracle adapter. | Any new `oracle` release, any vulnerability advisory for `paste`, any change to Oracle support, or every product release, whichever comes first. |

This is not a vulnerability allowlist. `cargo audit` must still run without
vulnerability findings; unmaintained warnings remain visible in CI. New
exceptions require a concrete dependency path, exposure analysis, owner decision,
and review trigger in this file.
