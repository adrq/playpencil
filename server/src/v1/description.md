The `/v1` HTTP API of the Playpencil sandbox daemon (default `127.0.0.1:7070`).

**Compatibility.** Unknown request fields are ignored. Clients must tolerate unknown response fields and unlisted values, including notice codes.

**Errors** are RFC 9457 problem details, except the bodiless health `503`. An unreadable, malformed (trailing content included) or non-JSON body, or an unparseable query string, gets a bare `400`; any other invalid request gets `422` `invalid_input`. Integers must be plain JSON integers (no fraction, exponent or `-0`). `401` and `403` are reserved and not returned by this version.

Timestamps are RFC 3339; binary data is base64.

**Environment.** `env` maps are written as `{NAME: value}` and read back as names only. A process gets the baseline, then the sandbox's `config.env`, then its own `env` (later wins); `PLAYPENCIL_*` names are removed and nothing is inherited. Baseline: `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `TERM=xterm`, `LANG=C`, `LC_ALL=C`, and `HOME`: /root when the effective uid is 0; otherwise no baseline value — the sandbox's config.env or the command spec must supply it. A non-root process whose layered environment has no `HOME` is `422` with `field` `env`, refused by the create, cold PATCH or spawn that produces it.

**Defaults.** Stop grace 5 s (flush, then kill). Reap tolerance 60 s.
