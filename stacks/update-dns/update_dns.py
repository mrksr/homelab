#!/usr/bin/env python3
"""Keep `<name>.internal` rewrites in AdGuard Home in sync with Proxmox and Unifi.

Principle: `<host>.internal` is the hostname a device uses for itself (the one it announces as
`<host>.local` over mDNS), served centrally so it does not depend on multicast.

Every source claims names; when two claims want the same name, the better tier wins:

  0. Proxmox cluster nodes (name and IP from /cluster/status)
  1. Proxmox guest hostnames: LXC config hostname, VM hostname from the QEMU guest agent
  2. Unifi client hostnames: the DHCP hostname a device reports (phones, Shellys, appliances, NAS)
  3. Proxmox VM labels, where they differ from the hostname (VM 109 label `hassio`, hostname `homeassistant`)
  4. Unifi aliases and local DNS records set by hand
Within the Unifi tiers, clients Unifi sees as active win over stored records.

Several VLANs: a host with NICs in more than one VLAN gets the plain name on its best VLAN by
VLAN_ORDER (services, default, admin, services-hetzner, privacy) and `<name>-<vlan>` on every other
one. A NIC's VLAN is the Unifi network whose subnet holds its IPv4 address. Single-NIC hosts never get
a suffix. Hostnames and labels get suffixes; aliases are tied to one MAC and stay as they are.

IPs: Proxmox guests live from Proxmox (LXC /interfaces, VM guest agent), Unifi clients from the live
station table, else the stored record. IPv6: global addresses; a ULA only if there is no global one.
Records with a Proxmox MAC that no longer belongs to any guest are ignored.

Hostnames are sticky: the last hostname seen per guest and per MAC is kept in the state file, so a
record that turns up without a hostname keeps its name. A name changes only when the device reports a
different hostname.

Why: Unifi's stored client records are only updated on connect events, and the DHCP hostname is
last-writer-wins. The old script deleted a name the moment one Unifi field went missing, and only a
manual "forget client" in Unifi brought it back.

Safety rules:
- A name that disappears from the sources is kept for GRACE_SECONDS before it is removed.
  An IP change of a name that still exists applies immediately.
- Names whose source could not be read (node offline, API error) are never removed.
- Adds run before removals; each AdGuard call is handled on its own.
- At most MAX_REMOVALS names may vanish per run; more means something is wrong upstream.
- Only `*.<DOMAIN>` rewrites are touched.

Usage: update_dns.py [--once] [--dry-run]. Configuration via environment (see config.example.env).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("update-dns")

NIC_MODELS = {"virtio", "e1000", "e1000e", "rtl8139", "vmxnet3", "ne2k_pci", "pcnet", "i82551", "i82557b", "i82559er"}


# --------------------------------------------------------------------------------------------- config

@dataclass
class Config:
    domain: str
    unifi_url: str
    unifi_user: str
    unifi_pass: str
    ag_url: str
    ag_user: str
    ag_pass: str
    pve_url: str
    pve_token_id: str
    pve_token_secret: str
    unifi_site: str = "default"
    pve_verify_tls: bool = False
    pve_mac_prefixes: tuple[str, ...] = ("bc:24:11",)
    vlan_order: tuple[str, ...] = ("services", "default", "admin", "services-hetzner", "privacy")
    include_ipv6: bool = True
    grace_seconds: int = 900
    max_removals: int = 10
    interval: int = 60
    state_file: str = "/data/state.json"
    ntfy_url: str = ""
    ntfy_token: str = ""

    @classmethod
    def from_env(cls, env: dict[str, str]) -> "Config":
        # Komodo/compose pass-through can deliver set-but-empty variables: treat those as unset.
        env = {k: v for k, v in env.items() if v.strip()}
        missing = [k for k in ("DOMAIN", "UNIFI_URL", "UNIFI_USER", "UNIFI_PASS", "AG_URL", "AG_USER", "AG_PASS",
                               "PVE_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET") if not env.get(k)]
        if missing:
            raise SystemExit(f"Missing settings: {', '.join(missing)} (see config.example.env)")

        def as_bool(key: str, default: bool) -> bool:
            return env.get(key, str(default)).strip().lower() in ("1", "true", "yes", "on")

        vlan_order = tuple(norm_vlan(v) for v in
                           env.get("VLAN_ORDER", "services,default,admin,services-hetzner,privacy").split(",") if v.strip())

        return cls(
            domain=env["DOMAIN"].strip("."),
            unifi_url=env["UNIFI_URL"].rstrip("/"),
            unifi_user=env["UNIFI_USER"],
            unifi_pass=env["UNIFI_PASS"],
            ag_url=env["AG_URL"].rstrip("/"),
            ag_user=env["AG_USER"],
            ag_pass=env["AG_PASS"],
            pve_url=env["PVE_URL"].rstrip("/"),
            pve_token_id=env["PVE_TOKEN_ID"],
            pve_token_secret=env["PVE_TOKEN_SECRET"],
            unifi_site=env.get("UNIFI_SITE", "default"),
            pve_verify_tls=as_bool("PVE_VERIFY_TLS", False),
            pve_mac_prefixes=tuple(p.strip().lower() for p in env.get("PVE_MAC_PREFIXES", "bc:24:11").split(",") if p.strip()),
            vlan_order=vlan_order,
            include_ipv6=as_bool("INCLUDE_IPV6", True),
            grace_seconds=int(env.get("GRACE_SECONDS", "900")),
            max_removals=int(env.get("MAX_REMOVALS", "10")),
            interval=int(env.get("INTERVAL", "60")),
            state_file=env.get("STATE_FILE", "/data/state.json"),
            ntfy_url=env.get("NTFY_URL", ""),
            ntfy_token=env.get("NTFY_TOKEN", ""),
        )


# ---------------------------------------------------------------------------------------------- model

@dataclass
class Nic:
    key: str            # net0, net1, ...
    mac: str            # lower case
    bridge: str


@dataclass
class Guest:
    vmid: int
    kind: str           # lxc | qemu
    node: str
    name: str           # Proxmox label (for LXC this is the hostname)
    status: str         # running | stopped | unknown
    nics: list[Nic] | None          # None: config could not be read
    ips_by_mac: dict[str, list[str]] | None = None   # None: live IPs could not be read
    hostname: str | None = None     # the guest's own hostname, None if unknown


@dataclass
class Network:
    name: str                           # normalised Unifi network name, e.g. "services", "default"
    subnet: ipaddress.IPv4Network


@dataclass
class Node:
    name: str
    ip: str
    online: bool


@dataclass
class Desired:
    records: dict[str, set[str]] = field(default_factory=dict)   # domain -> answers
    sources: dict[str, str] = field(default_factory=dict)        # domain -> human readable source
    macs: dict[str, str] = field(default_factory=dict)           # domain -> MAC it came from
    protected: set[str] = field(default_factory=set)             # domains that must not be removed this run
    notes: list[str] = field(default_factory=list)               # problems worth a notification
    known: dict[str, str] = field(default_factory=dict)          # sticky hostnames: guest:<vmid> / mac:<mac>

    def add(self, domain: str, ips: set[str], source: str, mac: str = "") -> None:
        if not ips:
            return
        self.records.setdefault(domain, set()).update(ips)
        self.sources.setdefault(domain, source)
        if mac:
            self.macs.setdefault(domain, mac)


# -------------------------------------------------------------------------------------------- helpers

def norm_mac(mac: str | None) -> str:
    return (mac or "").strip().lower()


ULA = ipaddress.ip_network("fc00::/7")


def usable_ips(addresses, include_ipv6: bool) -> set[str]:
    """Filter to addresses worth publishing: no loopback, link-local, or unparsable values.

    IPv6: global addresses first, local (ULA) second. ULAs are only published for an interface or client
    that has no global IPv6 address.
    """
    out = set()
    for raw in addresses or []:
        if not raw:
            continue
        try:
            ip = ipaddress.ip_address(str(raw).split("%")[0])
        except ValueError:
            log.debug("Ignoring unparsable address %r", raw)
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            continue
        if ip.version == 6 and not include_ipv6:
            continue
        out.add(str(ip))
    if any(":" in a and ipaddress.ip_address(a) not in ULA for a in out):
        out = {a for a in out if ":" not in a or ipaddress.ip_address(a) not in ULA}
    return out


def parse_net(value: str) -> tuple[str, str]:
    """Return (mac, bridge) from a Proxmox netX config value (LXC or QEMU style)."""
    mac = bridge = ""
    for part in value.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k == "hwaddr" or k in NIC_MODELS:
            mac = norm_mac(v)
        elif k == "bridge":
            bridge = v
    return mac, bridge


def norm_vlan(name: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", name.strip().lower()).strip("-")


def dns_label(name: str | None) -> str:
    """A device-reported name as a DNS label: lower case, first label only, spaces etc. become '-'.

    Underscores stay (existing names like `petkit_t4` use them; AdGuard accepts them).
    """
    first = (name or "").strip().lower().split(".")[0]
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9_-]+", "-", first)).strip("-")


def vlan_of(ips: set[str], networks: list[Network], fallback: str) -> str:
    """The VLAN an interface is in: the network holding its IPv4 address, else the fallback name ("" = unknown)."""
    for ip in sorted(ips):
        if ":" in ip:
            continue
        addr = ipaddress.ip_address(ip)
        for n in networks:
            if addr in n.subnet:
                return n.name
    return norm_vlan(fallback)


def vlan_suffixes(vlans: list[str], order: tuple[str, ...]) -> dict[str, str]:
    """Suffix per VLAN for one host: none for a single VLAN; else the best VLAN by `order` stays plain.

    An unknown VLAN ("") never gets a suffix and does not count as a second VLAN.
    """
    ranked = sorted(set(vlans) - {""}, key=lambda v: (order.index(v) if v in order else len(order), v))
    return {v: ("" if i == 0 else "-" + v) for i, v in enumerate(ranked)}


def unifi_hostname(user: dict | None, active: dict | None) -> str:
    """The DHCP hostname the device reports, live record first."""
    for rec in (active, user):
        if rec and rec.get("hostname"):
            return dns_label(rec["hostname"])
    return ""


def unifi_extra_names(user: dict | None, active: dict | None) -> list[str]:
    """Names set by hand in Unifi: local DNS record and alias."""
    out = []
    for rec in (user, active):
        if rec and rec.get("local_dns_record_enabled") and rec.get("local_dns_record"):
            out.append(dns_label(rec["local_dns_record"]))
        if rec and rec.get("name"):
            out.append(dns_label(rec["name"]))
    return [n for n in out if n]


def unifi_ips(user: dict | None, active: dict | None, include_ipv6: bool) -> set[str]:
    if active:
        v4 = [active.get("ip")]
        v6 = active.get("ipv6") or active.get("last_ipv6") or (user or {}).get("last_ipv6") or []
    else:
        user = user or {}
        v4 = [user.get("last_ip")]
        if user.get("use_fixedip"):
            v4.append(user.get("fixed_ip"))
        v6 = user.get("last_ipv6") or []
    if isinstance(v6, str):
        v6 = [v6]
    return usable_ips(list(v4) + list(v6), include_ipv6)


# ------------------------------------------------------------------------------------- desired state

TIER_NODE, TIER_GUEST, TIER_UNIFI, TIER_LABEL, TIER_ALIAS = range(5)
TIER_NAMES = ("pve node", "pve hostname", "unifi hostname", "pve label", "unifi alias")


@dataclass
class Claim:
    tier: int
    ips: set[str]
    source: str
    mac: str = ""
    active: bool = True


def build_desired(guests: list[Guest], users: list[dict], active: list[dict], cfg: Config,
                  nodes: list[Node] | None = None, known: dict[str, str] | None = None,
                  networks: list[Network] | None = None) -> Desired:
    d = Desired(known=dict(known or {}))
    networks = networks or []
    users_by_mac = {norm_mac(u.get("mac")): u for u in users}
    active_by_mac = {norm_mac(a.get("mac")): a for a in active}
    claims: dict[str, list[Claim]] = {}

    def fqdn(name: str) -> str:
        return name.strip().lower() + "." + cfg.domain

    def claim(name: str, c: Claim) -> None:
        if name.strip() and c.ips:
            claims.setdefault(fqdn(name), []).append(c)

    # Proxmox nodes (their bridges carry Proxmox MACs, so Unifi alone would treat them as orphans)
    for n in nodes or []:
        claim(n.name, Claim(TIER_NODE, usable_ips([n.ip], False), f"pve node {n.name}"))
        if not n.online:
            d.protected.add(fqdn(n.name))

    # Proxmox guests
    guest_macs: set[str] = set()
    for g in guests:
        label = dns_label(g.name)
        if dns_label(g.hostname):
            d.known[f"guest:{g.vmid}"] = dns_label(g.hostname)
        host = d.known.get(f"guest:{g.vmid}") if not dns_label(g.hostname) else dns_label(g.hostname)
        host = host or label
        if not host:
            continue
        if g.nics is None:
            # Config unreadable: NICs unknown, so keep anything that looks like this guest.
            for base in {host, label} - {""}:
                d.protected.add(fqdn(base))
                d.protected.update(fqdn(f"{base}-{n.name}") for n in networks)
            d.notes.append(f"{g.kind} {g.vmid} {host}: config unreadable on {g.node}, keeping its records")
            continue
        guest_macs.update(nic.mac for nic in g.nics if nic.mac)
        if g.status == "stopped":
            continue  # no IPs: names fall into the grace period, then go

        per_nic: list[tuple[Nic, set[str], str, bool]] = []
        for nic in g.nics:
            if not nic.mac:
                continue
            ips: set[str] = set()
            if g.ips_by_mac is not None:
                ips = usable_ips(g.ips_by_mac.get(nic.mac, []), cfg.include_ipv6)
            fallback = False
            if not any(":" not in ip for ip in ips):
                # No live IPv4 from Proxmox (agent missing, API error, node unknown): fall back to Unifi
                extra = unifi_ips(users_by_mac.get(nic.mac), active_by_mac.get(nic.mac), cfg.include_ipv6)
                ips |= extra
                fallback = True
                why = "no live IP from Proxmox" if g.ips_by_mac is not None else "live IPs unreadable"
                d.notes.append(f"{g.kind} {g.vmid} {host} {nic.key}: {why}; "
                               f"{'using Unifi ' + ','.join(sorted(extra)) if extra else 'no IP at all'}")
            per_nic.append((nic, ips, vlan_of(ips, networks, nic.bridge), fallback))

        suffix = vlan_suffixes([v for _, _, v, _ in per_nic], cfg.vlan_order)
        for nic, ips, vlan, fallback in per_nic:
            sfx = suffix.get(vlan, "")
            src = f"{g.kind}/{g.vmid} {nic.key} ({vlan})"
            claim(host + sfx, Claim(TIER_GUEST, ips, f"pve hostname {src}", nic.mac))
            if fallback:
                d.protected.add(fqdn(host + sfx))
            if label and label != host:
                claim(label + sfx, Claim(TIER_LABEL, ips, f"pve label {src}", nic.mac))
            for alias in unifi_extra_names(users_by_mac.get(nic.mac), active_by_mac.get(nic.mac)):
                claim(alias, Claim(TIER_ALIAS, ips, f"unifi alias of {src}", nic.mac))

    # Unifi clients that are not Proxmox guests
    by_host: dict[str, list[tuple[str, set[str], str, bool]]] = {}
    orphans = unnamed = 0
    for mac in set(users_by_mac) | set(active_by_mac):
        if not mac or mac in guest_macs:
            continue
        user, act = users_by_mac.get(mac), active_by_mac.get(mac)
        if mac.startswith(cfg.pve_mac_prefixes):
            orphans += 1
            log.debug("Ignoring Unifi client %s (%s): Proxmox MAC without a guest", mac, unifi_hostname(user, act))
            continue
        hostname = unifi_hostname(user, act)
        if hostname:
            d.known[f"mac:{mac}"] = hostname
        else:
            hostname = d.known.get(f"mac:{mac}", "")
            if hostname:
                log.debug("Unifi reports no hostname for %s; keeping %s", mac, hostname)
        aliases = unifi_extra_names(user, act)
        if not hostname and not aliases:
            unnamed += 1
            continue
        ips = unifi_ips(user, act, cfg.include_ipv6)
        if not ips:
            continue
        is_active = act is not None
        vlan = vlan_of(ips, networks, (act or {}).get("network", ""))
        if hostname:
            by_host.setdefault(hostname, []).append((mac, ips, vlan, is_active))
        for alias in aliases:
            claim(alias, Claim(TIER_ALIAS, ips, f"unifi alias {mac} ({vlan})", mac, is_active))

    for hostname, clients in by_host.items():
        considered = [c for c in clients if c[3]] or clients  # stale records only count if nothing is active
        suffix = vlan_suffixes([c[2] for c in considered], cfg.vlan_order)
        for mac, ips, vlan, is_active in considered:
            claim(hostname + suffix.get(vlan, ""), Claim(TIER_UNIFI, ips, f"unifi hostname {mac} ({vlan})", mac, is_active))

    # Resolve: best tier wins; within a tier, active claims win over stale ones.
    for domain, cs in claims.items():
        best = min(c.tier for c in cs)
        winners = [c for c in cs if c.tier == best]
        winners = [c for c in winners if c.active] or winners
        for c in winners:
            d.add(domain, c.ips, c.source, c.mac)
        losers = [c for c in cs if c.tier != best]
        if losers:
            log.debug("%s: %s wins over %s", domain, TIER_NAMES[best], ", ".join(sorted({TIER_NAMES[c.tier] for c in losers})))

    log.debug("Unifi: %d unnamed clients, %d orphaned Proxmox MACs ignored", unnamed, orphans)
    return d


# ---------------------------------------------------------------------------------------------- plan

@dataclass
class Plan:
    add: list[tuple[str, str]]
    remove: list[tuple[str, str]]
    pending: dict[str, float]      # domain -> first time it was missing
    held: list[str]                # domains kept only because of the grace period or protection


def make_plan(current: dict[str, set[str]], desired: Desired, pending: dict[str, float],
              now: float, cfg: Config) -> Plan:
    add, remove, held = [], [], []
    new_pending: dict[str, float] = {}

    for domain, ips in sorted(desired.records.items()):
        for ip in sorted(ips - current.get(domain, set())):
            add.append((domain, ip))

    for domain, ips in sorted(current.items()):
        want = desired.records.get(domain)
        if want:
            # Name still exists: stale answers go now, unless the source was unreadable.
            if domain not in desired.protected:
                remove.extend((domain, ip) for ip in sorted(ips - want))
            continue
        if domain in desired.protected:
            held.append(domain)
            continue
        since = pending.get(domain, now)
        if now - since >= cfg.grace_seconds:
            remove.extend((domain, ip) for ip in sorted(ips))
        else:
            new_pending[domain] = since
            held.append(domain)

    return Plan(add, remove, new_pending, held)


# --------------------------------------------------------------------------------------------- I/O

class Proxmox:
    def __init__(self, cfg: Config):
        self.s = requests.Session()
        self.s.verify = cfg.pve_verify_tls
        self.s.headers["Authorization"] = f"PVEAPIToken={cfg.pve_token_id}={cfg.pve_token_secret}"
        self.base = cfg.pve_url + "/api2/json"

    def get(self, path: str):
        r = self.s.get(self.base + path, timeout=15)
        r.raise_for_status()
        return r.json()["data"]

    def nodes(self) -> list[Node]:
        return [Node(n["name"], n.get("ip", ""), bool(n.get("online")))
                for n in self.get("/cluster/status") if n.get("type") == "node"]

    def guests(self) -> list[Guest]:
        out = []
        for res in self.get("/cluster/resources?type=vm"):
            if res.get("template"):
                continue
            kind, node, vmid = res["type"], res["node"], res["vmid"]
            status = res.get("status") if res.get("status") in ("running", "stopped") else "unknown"
            g = Guest(vmid=vmid, kind=kind, node=node, name=res.get("name", ""), status=status, nics=None)
            try:
                conf = self.get(f"/nodes/{node}/{kind}/{vmid}/config")
                g.nics = []
                for key in sorted(k for k in conf if k.startswith("net") and k[3:].isdigit()):
                    mac, bridge = parse_net(conf[key])
                    g.nics.append(Nic(key, mac, bridge))
            except requests.RequestException as e:
                log.warning("Proxmox: cannot read config of %s %s on %s: %s", kind, vmid, node, e)
            if kind == "lxc":
                g.hostname = g.name
            elif status == "running":
                g.hostname = self._agent_hostname(node, vmid)
            if status == "running" and g.nics is not None:
                g.ips_by_mac = self._live_ips(kind, node, vmid)
            out.append(g)
        if not out:
            raise RuntimeError("Proxmox returned no guests")
        return out

    def _agent_hostname(self, node: str, vmid: int) -> str | None:
        try:
            return self.get(f"/nodes/{node}/qemu/{vmid}/agent/get-host-name")["result"]["host-name"] or None
        except (requests.RequestException, KeyError, TypeError) as e:
            log.info("Proxmox: no hostname from the guest agent of VM %s: %s", vmid, e)
            return None

    def _live_ips(self, kind: str, node: str, vmid: int) -> dict[str, list[str]] | None:
        try:
            if kind == "lxc":
                ifaces = self.get(f"/nodes/{node}/lxc/{vmid}/interfaces")
            else:
                ifaces = self.get(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")["result"]
        except (requests.RequestException, KeyError, TypeError) as e:
            log.info("Proxmox: no live IPs for %s %s: %s", kind, vmid, e)
            return None
        out: dict[str, list[str]] = {}
        for i in ifaces or []:
            mac = norm_mac(i.get("hardware-address") or i.get("hwaddr"))
            if mac:
                out.setdefault(mac, []).extend(a.get("ip-address") for a in i.get("ip-addresses") or [])
        return out


def unifi_clients(cfg: Config) -> tuple[list[dict], list[dict], list[Network]]:
    with requests.Session() as s:
        s.verify = False
        s.post(cfg.unifi_url + "/api/auth/login",
               data={"username": cfg.unifi_user, "password": cfg.unifi_pass}, timeout=15).raise_for_status()
        base = f"{cfg.unifi_url}/proxy/network/api/s/{cfg.unifi_site}"
        users = s.get(base + "/list/user", timeout=30)
        users.raise_for_status()
        active = s.get(base + "/stat/sta", timeout=30)
        active.raise_for_status()
        nets = s.get(base + "/rest/networkconf", timeout=30)
        nets.raise_for_status()
        networks = []
        for n in nets.json()["data"]:
            try:
                if n.get("ip_subnet") and n.get("name"):
                    networks.append(Network(norm_vlan(n["name"]), ipaddress.ip_network(n["ip_subnet"], strict=False)))
            except ValueError:
                log.debug("Ignoring network %s with subnet %r", n.get("name"), n.get("ip_subnet"))
        return users.json()["data"], active.json()["data"], networks


class AdGuard:
    def __init__(self, cfg: Config):
        self.s = requests.Session()
        self.s.auth = (cfg.ag_user, cfg.ag_pass)
        self.base = cfg.ag_url + "/control"
        self.suffix = "." + cfg.domain

    def current(self) -> dict[str, set[str]]:
        r = self.s.get(self.base + "/rewrite/list", timeout=15)
        r.raise_for_status()
        out: dict[str, set[str]] = {}
        for rec in r.json():
            if rec["domain"].endswith(self.suffix):
                out.setdefault(rec["domain"], set()).add(rec["answer"])
        return out

    def apply(self, plan: Plan) -> int:
        errors = 0
        for verb, items in (("add", plan.add), ("delete", plan.remove)):
            for domain, ip in items:
                body: dict[str, object] = {"domain": domain, "answer": ip}
                if verb == "add":
                    body["enabled"] = True
                try:
                    self.s.post(f"{self.base}/rewrite/{verb}", json=body, timeout=15).raise_for_status()
                    log.info("%s %s -> %s", "Added" if verb == "add" else "Removed", domain, ip)
                except requests.RequestException as e:
                    errors += 1
                    log.error("Could not %s %s -> %s: %s", verb, domain, ip, e)
        return errors


def notify(cfg: Config, title: str, message: str) -> None:
    if not cfg.ntfy_url:
        return
    headers = {"Title": title}
    if cfg.ntfy_token:
        headers["Authorization"] = f"Bearer {cfg.ntfy_token}"
    try:
        requests.post(cfg.ntfy_url, data=message.encode(), headers=headers, timeout=10)
    except requests.RequestException as e:
        log.warning("ntfy failed: %s", e)


def load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        log.warning("Ignoring unreadable state file %s: %s", path, e)
        return {}


def save_state(path: str, state: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


# --------------------------------------------------------------------------------------------- run

def run_once(cfg: Config, state: dict, dry_run: bool) -> dict:
    now = time.time()
    pve = Proxmox(cfg)
    nodes, guests = pve.nodes(), pve.guests()
    users, active, networks = unifi_clients(cfg)
    desired = build_desired(guests, users, active, cfg, nodes, state.get("hostnames", {}), networks)
    if not desired.records:
        raise RuntimeError("No desired records at all; refusing to touch AdGuard")

    ag = AdGuard(cfg)
    current = ag.current()
    plan = make_plan(current, desired, state.get("pending", {}), now, cfg)

    # Why did a name go missing? Log what the sources say about it now (once, when it starts).
    last_sources = state.get("sources", {})
    last_macs = state.get("macs", {})
    users_by_mac = {norm_mac(u.get("mac")): u for u in users}
    active_by_mac = {norm_mac(a.get("mac")): a for a in active}
    for domain in plan.pending:
        if domain not in state.get("pending", {}):
            mac = last_macs.get(domain, "")
            keep = ("name", "hostname", "local_dns_record", "local_dns_record_enabled", "last_ip",
                    "fixed_ip", "use_fixedip", "ip", "last_seen", "network")
            snap = {k: v for k, v in (users_by_mac.get(mac) or {}).items() if k in keep}
            live = {k: v for k, v in (active_by_mac.get(mac) or {}).items() if k in keep}
            log.warning("Name %s is no longer in any source (last: %s); removing in %ds unless it comes back. "
                        "Unifi record of %s now: %s; live: %s", domain, last_sources.get(domain, "?"),
                        cfg.grace_seconds, mac or "?", json.dumps(snap), json.dumps(live) if live else "not active")

    # Guard against an upstream returning garbage: limit how many names may vanish in one run.
    # IP changes of names that still exist are not limited.
    blocked: list[tuple[str, str]] = []
    vanishing = {domain for domain, _ in plan.remove if domain not in desired.records}
    if len(vanishing) > cfg.max_removals:
        msg = f"{len(vanishing)} names would vanish (limit {cfg.max_removals}); keeping them this run"
        log.error(msg)
        desired.notes.append(msg)
        blocked = [r for r in plan.remove if r[0] in vanishing]
        plan.remove = [r for r in plan.remove if r[0] not in vanishing]

    for line in desired.notes:
        log.warning(line)
    log.info("%d names wanted, %d to add, %d to remove, %d held", len(desired.records), len(plan.add),
             len(plan.remove), len(plan.held))

    if dry_run:
        for domain, ip in plan.add:
            log.info("[dry-run] would add %s -> %s  (%s)", domain, ip, desired.sources.get(domain))
        for domain, ip in plan.remove:
            log.info("[dry-run] would remove %s -> %s", domain, ip)
        for domain, ip in blocked:
            log.info("[dry-run] would remove %s -> %s, but blocked by MAX_REMOVALS", domain, ip)
        for domain in plan.held:
            log.info("[dry-run] holding %s %s", domain, sorted(current.get(domain, [])))
        return state

    errors = ag.apply(plan)
    if plan.remove:
        notify(cfg, "update-dns removed records", "\n".join(f"{d} -> {ip}" for d, ip in plan.remove))

    notes = sorted(desired.notes)
    if notes != state.get("notes", []) and notes:
        notify(cfg, "update-dns: check DNS sources", "\n".join(notes))

    return {
        "pending": plan.pending,
        "sources": {**last_sources, **desired.sources},
        "macs": {**last_macs, **desired.macs},
        "notes": notes,
        "errors": errors,
        "hostnames": desired.known,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Sync <name>.internal rewrites in AdGuard Home from Proxmox and Unifi.")
    ap.add_argument("--once", action="store_true", help="run one pass and exit")
    ap.add_argument("--dry-run", action="store_true", help="show changes, write nothing (implies --once)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    cfg = Config.from_env(dict(os.environ))
    state = load_state(cfg.state_file)
    failures = 0
    while True:
        try:
            state = run_once(cfg, state, args.dry_run)
            if not args.dry_run:
                save_state(cfg.state_file, state)
            failures = 0
        except Exception as e:  # keep the loop alive; nothing is removed on a failed run
            failures += 1
            log.exception("Run failed (%d in a row): %s", failures, e)
            if failures == 5:
                notify(cfg, "update-dns failing", f"5 runs in a row failed, last error: {e}")
            if args.once or args.dry_run:
                sys.exit(1)
        if args.once or args.dry_run:
            return
        time.sleep(cfg.interval)


if __name__ == "__main__":
    main()
