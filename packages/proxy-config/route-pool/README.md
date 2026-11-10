# tor-socks5-route-pool

Routing logic for proxy pools used as the pre or post hop of the tor-socks5
chain. The crate is transport-agnostic: it decides which pool member to try
for a target site and records the outcome; the caller performs the dial.

- `site_key` maps a target host to its registrable domain (eTLD+1), so one
  site keeps using one pool member while different sites spread across members.
- `PoolScope` wraps the `resocks5-net` rotator: sticky assignment, deterministic
  home member, weighted failover order and quarantine of failing members.
- `run_attempts` tries members one after another until the deadline and never
  leaves the configured pool.
- `probe_round` / `drive_probes` re-check quarantined members in the background.
