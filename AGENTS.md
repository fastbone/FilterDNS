# AGENTS.md

## Cursor Cloud specific instructions

FilterDNS is a single .NET 10 console app (`FilterDns/FilterDns.csproj`, solution `FilterDns.sln`). It is a DNS "master" proxy: it pulls a zone from an upstream master via AXFR/IXFR, filters/rewrites it (replaces NS records, rewrites SOA mname/rname, optionally strips private/RFC1918 IPs), then re-serves it to slave DNS servers and answers health-check queries. State is files under `DataDirectory` (default `./data`); there is no database. There is no test project — the build itself is the lint/type check (`Nullable` is enabled).

### Environment / toolchain
- The .NET 10 SDK is installed user-local at `~/.dotnet` (not via apt). The update script reinstalls it idempotently. `~/.bashrc` already exports `DOTNET_ROOT=$HOME/.dotnet` and adds it to `PATH`; if `dotnet` is not found in a non-login shell, run `export PATH="$HOME/.dotnet:$PATH"` first.

### Build / run
- Build (also serves as lint/type check): `dotnet build FilterDns.sln`
- Run the proxy: `cd FilterDns && dotnet run` (reads `FilterDns/appsettings.json`).
- Export/filter a zone without starting the server: `cd FilterDns && dotnet run -- export <zone>`.

### Config gotcha (important)
- `FilterDns/appsettings.json` is **git-ignored** (see `.gitignore`) and is **required** — the app throws `No zones configured` at startup if it is missing. Copy `FilterDns/appsettings.example.json` to `FilterDns/appsettings.json` and edit zones. A working local-test config is already present at `FilterDns/appsettings.json` in this VM (proxy on `127.0.0.1:5353`, upstream `127.0.0.1:5300`).
- Binding the default DNS port 53 needs root; for local testing set `Server.ListenPort` to a high port (e.g. `5353`). Only IPs in `XferWhitelist`/`Slaves` may AXFR, and only IPs in `HealthCheckAcl` get answers to normal queries.

### End-to-end testing (needs an upstream master)
- To exercise the proxy end-to-end you need an upstream master DNS that allows AXFR. `bind9` is installed for this. A ready-made test master config lives at `~/dns-test/named.conf` serving `example.com` (with internal NS + private IPs) on `127.0.0.1:5300`.
- Start the upstream master: `named -g -c ~/dns-test/named.conf` (rndc/port-953 "permission denied" lines are harmless).
- Verify filtering through the proxy: `dig @127.0.0.1 -p 5353 example.com AXFR` — internal NS records become `*.publicdns.example`, SOA is rewritten, and private-IP records (`internal`, `secret`) are dropped.
