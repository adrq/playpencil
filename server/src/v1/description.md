The `/v1` HTTP API of the Playpencil sandbox daemon (default `127.0.0.1:7070`).

**Compatibility.** Unknown request fields are ignored. Clients must tolerate unknown response fields and unlisted values, including notice codes.

**Errors** are RFC 9457 problem details, except the bodiless health `503`. An unreadable, malformed (trailing content included) or non-JSON body, or an unparseable query string, gets a bare `400`; any other invalid request gets `422` `invalid_input`. Integers must be plain JSON integers (no fraction, exponent or `-0`). `401` and `403` are reserved and not returned by this version.

Writes return `202`; read convergence from `status`. Timestamps are RFC 3339; binary data is base64.

**Environment.** `env` maps are written as `{NAME: value}` and read back as names only. A process gets the baseline, then the sandbox's `config.env`, then its own `env` (later wins); `PLAYPENCIL_*` names are removed and nothing is inherited. Baseline: `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `HOME=/root`, `TERM=xterm`, `LANG=C`, `LC_ALL=C`.

**Defaults.** Stop grace 5 s (flush, then kill). Reap tolerance 60 s.
