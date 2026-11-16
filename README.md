# Mahan Router

A Linux-based router OS meant to replace MikroTik RouterOS on standard x86 and
ARM hardware. The full design is in [docs/ARCHITECTURE.fa.md](docs/ARCHITECTURE.fa.md)
(Persian). [docs/STATUS.md](docs/STATUS.md) lists what is built and what is still missing.

> **Status:** phase 1 foundation only. The core agent, the config model, the
> renderers and the CLI work, and they pass an end-to-end lab test in network
> namespaces. None of it has run on a real device yet. There is no OS image,
> web panel, IPsec/OpenVPN or per-IP queues.

## How it works

```
             ┌──────────── management plane ────────────┐
  mrctl ───► │ REST API (Unix socket, or TCP with token) │ ◄─── web panel (later)
             └───────────────────┬──────────────────────┘
                                 │
             ┌─────────── control plane: mahan-agent ────────────┐
             │ YAML config ─► validate ─► render ─► precheck ─►   │
             │ write files ─► reload changed services ─► Git commit│
             │ commit-confirm timer ─► automatic rollback          │
             └───────────────────┬───────────────────────────────┘
                                 │ rendered files
  ┌──────────────┬──────────────┼──────────────┬────────────┬──────────┐
  nftables       systemd-networkd  FRR (OSPF/BGP) Kea DHCPv4   Unbound    chrony / pppd
  (filter, NAT)  (ports, VLAN,   
                 bridge, bond,
                 WireGuard, CAKE)
```

- **One declarative file** (`config.yaml`) describes the whole device. Every
  commit is a Git revision that you can diff and roll back.
- **Commit-confirm:** `mrctl commit --confirm 120` rolls back automatically
  unless you run `mrctl confirm` in time. A reboot during the window also
  rolls back, so a bad firewall rule cannot lock you out.
- **Safe apply:** every file is first checked by its own service checker
  (`nft -c`, `kea-dhcp4 -t`, `unbound-checkconf`, `vtysh -C`). If reloading
  a service fails, the previous files are put back.
- **RouterOS-style model:** interface names like `ether1`, interface lists
  (`WAN`/`LAN`), address lists (static and dynamic with timeout), filter
  chains `input`/`forward`/`output`, NAT chains `srcnat`/`dstnat`,
  `connection_state`, `connection_nat_state`, and per-rule counters.
- **The agent owns only its own nftables table** (`inet mahan`). Docker and
  other tables are left alone.

## Layout

| Path | Contents |
|---|---|
| `cmd/mahan-agent` | core-agent daemon |
| `cmd/mrctl` | CLI (talks to the agent; `validate`/`render` also work offline) |
| `internal/config` | schema, strict YAML parsing, validation, factory default |
| `internal/render` | pure renderers: nftables, networkd, Kea, Unbound, chrony, FRR, pppd |
| `internal/apply` | precheck, atomic writes, manifest of owned files, service reloads |
| `internal/store` | Git-backed running config + candidate |
| `internal/agent` | commit / confirm / rollback logic |
| `internal/api` | REST API |
| `examples/` | `factory-default.yaml`, `branch-office.yaml` |
| `tests/lab/` | network-namespace end-to-end test |
| `packaging/systemd/` | `mahan-agent.service`, `mahan-pppoe@.service` |

## Build and test

```bash
make build      # bin/mahan-agent, bin/mrctl
make test       # unit tests; checks rendered files with nft/kea/unbound if installed
make lab        # end-to-end test in network namespaces (root)
make cross      # static binaries for amd64, arm64, arm, mips, mipsle
```

The lab (`tests/lab/run.sh`) builds three namespaces (upstream, router,
client) and starts the agent in lab mode. It commits `tests/lab/lab.yaml`
through the API, loads the rendered ruleset into the router namespace, and
then checks:

- masquerade
- port forwarding
- input firewall
- static and dynamic address lists
- rule counters
- confirm timeout rollback
- manual rollback

## CLI

```bash
mrctl show                     # running config
mrctl edit                     # edit the candidate in $EDITOR
mrctl load my.yaml             # or load a file
mrctl diff                     # running vs candidate
mrctl commit -m "guest vlan" --confirm 120
mrctl confirm
mrctl history
mrctl rollback HEAD~1
mrctl counters                 # hits per rule: f<N> = firewall.filter[N], n<N> = firewall.nat[N]
mrctl render my.yaml --out /tmp/preview   # offline: see the generated files
```

## API (v1)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/config/running` | running YAML |
| GET/PUT/DELETE | `/api/v1/config/candidate` | candidate YAML |
| POST | `/api/v1/config/validate` | validate body (or candidate) |
| GET | `/api/v1/config/diff` | unified diff |
| GET | `/api/v1/config/render` | files the candidate would produce (secrets masked) |
| POST | `/api/v1/commit` | `{"message","confirm_seconds"}` |
| POST | `/api/v1/confirm` | keep a pending commit |
| GET | `/api/v1/history`, `/api/v1/history/{rev}` | revisions |
| POST | `/api/v1/rollback` | `{"revision": "HEAD~1"}` |
| GET | `/api/v1/status` | revision, pending confirm, `ip -j addr` |
| GET | `/api/v1/firewall/counters` | packets/bytes per rule tag |

The Unix socket needs no token, because it is root-only. The TCP listener
(`--listen`) requires `Authorization: Bearer <token>` from
`/etc/mahan-router/api-token`.

## Runtime dependencies on the device

Debian 12 packages:

- `systemd` (networkd)
- `nftables`
- `kea-dhcp4-server`
- `unbound`
- `chrony`
- `frr`
- `ppp`
- `wireguard-tools`
- `git`
