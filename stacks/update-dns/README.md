# update-dns

Keeps the `<name>.internal` rewrites in AdGuard Home (`dns`, 10.31.101.8) in sync. Replaces the
`proxmoxery/stacks/update-dns` script that the Komodo stack downloaded from GitHub every 30 s.

## Why

The old script read names only from Unifi's stored client list. That list is updated on connect events,
and the DHCP hostname in it is last-writer-wins. When a record lost its hostname, the script deleted
the DNS name in the next run, and only "forget client" in the Unifi UI brought it back. Details and evidence:
`claude-cowork/2026-11-internal-dns/`.

## Where names come from

`<host>.internal` is the hostname a device uses for itself (its `<host>.local` mDNS name), served centrally.
Every source claims names; on a conflict the better tier wins:

| Tier | Source | Names | IPs |
|---|---|---|---|
| 0 | Proxmox nodes (`/cluster/status`) | node name | cluster IP |
| 1 | Proxmox guests | LXC hostname; VM hostname from the guest agent | live from Proxmox (LXC `/interfaces`, VM guest agent); Unifi as fallback |
| 2 | Unifi clients that are not Proxmox guests | DHCP hostname the device reports | live station table first, stored record otherwise |
| 3 | Proxmox VM labels | label, where it differs from the hostname (`hassio`) | as the guest |
| 4 | Unifi aliases, local DNS records | as set in Unifi | as the client |

- **Several VLANs:** a host with NICs in more than one VLAN keeps the plain name on its best VLAN by `VLAN_ORDER`
  (services, default, admin, services-hetzner, privacy) and gets `<host>-<vlan>` on the others (`dns-default`).
  A NIC's VLAN is the Unifi network whose subnet holds its IPv4. Single-NIC hosts never get a suffix.
- **Sticky hostnames:** the last hostname per guest and per MAC is kept in the state file, so a Unifi record without
  a hostname, or a guest agent that does not answer, does not lose the name.
- **IPv6:** global addresses; a ULA only for a NIC without a global one.
- Unifi records with a Proxmox MAC that belongs to no guest any more (deleted LXCs) are ignored.
- Within the Unifi tiers, clients Unifi sees as active win over stored records.

The full design with diagrams: `claude-cowork/2026-11-internal-dns/design.md`.

## Safety

- A name that vanishes from all sources is kept for `GRACE_SECONDS` (15 min), then removed. A changed IP of
  a name that still exists applies at once.
- Names whose source could not be read (node offline, API error, VM without agent) are never removed.
- At most `MAX_REMOVALS` names may vanish per run.
- Adds run before removals; a failed AdGuard call does not stop the others.
- Only `*.internal` rewrites are touched (`h.zfix.org` and friends stay).
- When a name starts its grace period, the log shows its last source and what Unifi says about that MAC now.
- Optional ntfy messages for removals, for sources that need a look, and after 5 failed runs in a row.

## Run

```sh
uv run pytest -q                              # tests
set -a; . ./.env; set +a
uv run update_dns.py --dry-run                # shows the plan, writes nothing
```

The Komodo stack: `compose.yaml` builds the image from this folder and keeps its state in a volume. Set the
variables from `config.example.env` in the stack's environment.

## Proxmox token

Read-only, on any home node:

```sh
pveum user add update-dns@pve --comment "AdGuard DNS sync, read-only"
pveum acl modify / --users update-dns@pve --roles PVEAuditor
pveum user token add update-dns@pve dns --privsep 0
```

`PVEAuditor` includes `VM.Audit` (configs, LXC interfaces) and `VM.GuestAgent.Audit` (VM IPs).
