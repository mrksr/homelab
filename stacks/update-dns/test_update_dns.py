"""Tests for the pure parts of update_dns: name derivation and the removal plan.

Run: uv run pytest -q
All MACs and addresses below are made up; the VLAN layout mirrors the real one.
"""

import ipaddress

from update_dns import (Config, Desired, Guest, Network, Nic, Node, build_desired, dns_label, make_plan,
                        parse_net, usable_ips, vlan_suffixes)

CFG = Config(domain="internal", unifi_url="", unifi_user="", unifi_pass="", ag_url="", ag_user="", ag_pass="",
             pve_url="", pve_token_id="", pve_token_secret="", grace_seconds=900, include_ipv6=True)

NETS = [Network(name, ipaddress.ip_network(net)) for name, net in [
    ("services", "10.1.0.0/24"), ("default", "10.0.0.0/24"), ("admin", "10.4.0.0/24"),
    ("services-hetzner", "10.2.0.0/24"), ("privacy", "10.3.0.0/24"), ("test", "10.5.0.0/24")]]


def lxc(vmid, name, nics, ips=None, status="running"):
    return Guest(vmid, "lxc", "pve1", name, status, [Nic(*n) for n in nics], ips, hostname=name)


def build(guests=(), users=(), active=(), nodes=None, known=None, cfg=CFG):
    return build_desired(list(guests), list(users), list(active), cfg, nodes, known, NETS)


# ------------------------------------------------------------------------------------------- basics

def test_parse_net_lxc_and_qemu():
    assert parse_net("name=eth0,bridge=services,hwaddr=BC:24:11:00:00:01,ip=dhcp,type=veth") == \
        ("bc:24:11:00:00:01", "services")
    assert parse_net("virtio=02:91:2D:00:00:02,bridge=vmbr0") == ("02:91:2d:00:00:02", "vmbr0")


def test_usable_ips_filters_noise():
    assert usable_ips(["10.0.0.1", "fe80::1", "127.0.0.1", "::1", "bogus", "", None, "2001:db8::1"], True) == \
        {"10.0.0.1", "2001:db8::1"}
    assert usable_ips(["10.0.0.1", "2001:db8::1"], False) == {"10.0.0.1"}


def test_ipv6_global_first_ula_only_as_fallback():
    assert usable_ips(["10.0.0.1", "2a02:db8::1", "fd55::1"], True) == {"10.0.0.1", "2a02:db8::1"}
    assert usable_ips(["10.0.0.1", "fd55::1", "fe80::1"], True) == {"10.0.0.1", "fd55::1"}


def test_empty_env_values_count_as_unset():
    env = {k: "x" for k in ("DOMAIN", "UNIFI_URL", "UNIFI_USER", "UNIFI_PASS", "AG_URL", "AG_USER", "AG_PASS",
                            "PVE_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET")}
    cfg = Config.from_env({**env, "GRACE_SECONDS": "", "INCLUDE_IPV6": " ", "NTFY_URL": "", "VLAN_ORDER": ""})
    assert cfg.grace_seconds == 900 and cfg.include_ipv6 is True and cfg.ntfy_url == ""
    assert cfg.vlan_order == ("services", "default", "admin", "services-hetzner", "privacy")


# ------------------------------------------------------------------------------------- VLAN suffixes

def test_vlan_suffixes_follow_the_order():
    order = CFG.vlan_order
    assert vlan_suffixes(["privacy"], order) == {"privacy": ""}
    assert vlan_suffixes(["default", "services"], order) == {"services": "", "default": "-default"}
    assert vlan_suffixes(["privacy", "default"], order) == {"default": "", "privacy": "-privacy"}
    assert vlan_suffixes(["test", "admin", "privacy"], order) == {"admin": "", "privacy": "-privacy", "test": "-test"}


def test_unknown_vlan_never_counts_as_second_vlan():
    assert vlan_suffixes(["default", ""], CFG.vlan_order) == {"default": ""}
    users = [{"mac": "aa:00:00:00:00:80", "hostname": "xps", "last_ip": "10.0.0.80"},
             {"mac": "aa:00:00:00:00:81", "hostname": "xps", "last_ipv6": ["2a02:db8::81"]}]  # no IPv4, VLAN unknown
    assert build([], users).records == {"xps.internal": {"10.0.0.80", "2a02:db8::81"}}


def test_single_nic_never_gets_a_suffix():
    g = lxc(118, "tailscale-home-router", [("net0", "bc:24:11:00:00:03", "vmbr0")],
            {"bc:24:11:00:00:03": ["10.0.0.160"]})
    assert set(build([g]).records) == {"tailscale-home-router.internal"}


def test_guest_in_many_vlans():
    nics = [("net0", "bc:24:11:00:00:10", "vmbr0"), ("net1", "bc:24:11:00:00:11", "services"),
            ("net2", "bc:24:11:00:00:12", "privacy"), ("net3", "bc:24:11:00:00:13", "servhznr")]
    ips = {"bc:24:11:00:00:10": ["10.0.0.8"], "bc:24:11:00:00:11": ["10.1.0.8"],
           "bc:24:11:00:00:12": ["10.3.0.8"], "bc:24:11:00:00:13": ["10.2.0.8"]}
    assert build([lxc(104, "dns", nics, ips)]).records == {
        "dns.internal": {"10.1.0.8"}, "dns-default.internal": {"10.0.0.8"},
        "dns-privacy.internal": {"10.3.0.8"}, "dns-services-hetzner.internal": {"10.2.0.8"}}


def test_multi_nic_without_services_uses_next_vlan_in_order():
    nics = [("net0", "bc:24:11:00:00:20", "vmbr0"), ("net1", "bc:24:11:00:00:21", "privacy")]
    g = lxc(200, "box", nics, {"bc:24:11:00:00:20": ["10.0.0.20"], "bc:24:11:00:00:21": ["10.3.0.20"]})
    assert build([g]).records == {"box.internal": {"10.0.0.20"}, "box-privacy.internal": {"10.3.0.20"}}


def test_vlan_comes_from_the_ip_not_the_bridge_name():
    nics = [("net0", "bc:24:11:00:00:30", "vmbr0"), ("net1", "bc:24:11:00:00:31", "weird-bridge")]
    g = lxc(300, "x", nics, {"bc:24:11:00:00:30": ["10.0.0.30"], "bc:24:11:00:00:31": ["10.1.0.30"]})
    assert build([g]).records == {"x.internal": {"10.1.0.30"}, "x-default.internal": {"10.0.0.30"}}


# --------------------------------------------------------------------------------- names and tiers

def test_proxmox_name_wins_and_ignores_missing_unifi_hostname():
    g = lxc(101, "jellyfin", [("net0", "bc:24:11:00:00:01", "services")], {"bc:24:11:00:00:01": ["10.1.0.10"]})
    users = [{"mac": "bc:24:11:00:00:01", "hostname": None, "name": None, "last_ip": "10.1.0.99"}]
    assert build([g], users).records == {"jellyfin.internal": {"10.1.0.10"}}


def test_vm_hostname_label_and_alias():
    # VM labelled "hassio" whose own hostname is "homeassistant", NICs in services and default.
    g = Guest(109, "qemu", "pve1", "hassio", "running",
              [Nic("net0", "02:00:00:00:00:01", "services"), Nic("net1", "bc:24:11:00:00:02", "vmbr0")],
              {"02:00:00:00:00:01": ["10.1.0.5", "fe80::1", "2001:db8::5"], "bc:24:11:00:00:02": ["10.0.0.171"]},
              hostname="homeassistant")
    users = [{"mac": "bc:24:11:00:00:02", "hostname": "homeassistant", "name": "ha-alias"}]
    d = build([g], users)
    assert d.records == {
        "homeassistant.internal": {"10.1.0.5", "2001:db8::5"},
        "homeassistant-default.internal": {"10.0.0.171"},
        "hassio.internal": {"10.1.0.5", "2001:db8::5"},
        "hassio-default.internal": {"10.0.0.171"},
        "ha-alias.internal": {"10.0.0.171"},
    }
    assert d.sources["homeassistant.internal"].startswith("pve hostname")
    assert d.sources["hassio.internal"].startswith("pve label")


def test_hostname_beats_label_and_alias_of_other_devices():
    a = lxc(1, "alpha", [("net0", "bc:24:11:00:00:40", "services")], {"bc:24:11:00:00:40": ["10.1.0.40"]})
    b = Guest(2, "qemu", "pve1", "alpha", "running", [Nic("net0", "bc:24:11:00:00:41", "services")],
              {"bc:24:11:00:00:41": ["10.1.0.41"]}, hostname="beta")   # label collides with a's hostname
    users = [{"mac": "aa:00:00:00:00:42", "hostname": "gamma", "name": "beta", "last_ip": "10.0.0.42"}]
    d = build([a, b], users)
    assert d.records["alpha.internal"] == {"10.1.0.40"}   # guest hostname beats b's label
    assert d.records["beta.internal"] == {"10.1.0.41"}    # guest hostname beats Unifi alias
    assert d.records["gamma.internal"] == {"10.0.0.42"}


def test_unifi_hostname_beats_unifi_alias():
    users = [{"mac": "aa:00:00:00:00:50", "hostname": "kaiser", "last_ip": "10.0.0.50"},
             {"mac": "aa:00:00:00:00:51", "hostname": "other", "name": "kaiser", "last_ip": "10.0.0.51"}]
    assert build([], users).records["kaiser.internal"] == {"10.0.0.50"}


def test_device_names_become_dns_labels():
    assert dns_label("Elgato Key Light Air 3F04") == "elgato-key-light-air-3f04"
    assert dns_label("petkit_T4") == "petkit_t4"
    assert dns_label("host.example.com") == "host"
    assert dns_label("  --weird!!name-- ") == "weird-name"
    users = [{"mac": "aa:00:00:00:00:90", "hostname": "Elgato Key Light Air 3F04", "name": "Elgato Office Left",
              "last_ip": "10.0.0.90"}]
    assert set(build([], users).records) == {"elgato-key-light-air-3f04.internal", "elgato-office-left.internal"}


def test_unifi_alias_is_an_extra_name():
    users = [{"mac": "aa:00:00:00:00:52", "hostname": "Kaiser", "name": "heating", "last_ip": "10.0.0.52"}]
    assert build([], users).records == {"kaiser.internal": {"10.0.0.52"}, "heating.internal": {"10.0.0.52"}}


def test_unifi_device_in_two_vlans():
    users = [{"mac": "aa:00:00:00:00:60", "hostname": "nas", "last_ip": "10.1.0.60"},
             {"mac": "aa:00:00:00:00:61", "hostname": "nas", "last_ip": "10.0.0.60"}]
    active = [{"mac": "aa:00:00:00:00:60", "hostname": "nas", "ip": "10.1.0.60"},
              {"mac": "aa:00:00:00:00:61", "hostname": "nas", "ip": "10.0.0.60"}]
    assert build([], users, active).records == {"nas.internal": {"10.1.0.60"}, "nas-default.internal": {"10.0.0.60"}}


def test_unifi_same_vlan_active_wins_and_stale_records_do_not_cause_suffixes():
    users = [{"mac": "aa:00:00:00:00:01", "hostname": "phone", "last_ip": "10.0.0.1"},
             {"mac": "aa:00:00:00:00:02", "hostname": "phone", "last_ip": "10.0.0.2"},
             {"mac": "aa:00:00:00:00:03", "hostname": "phone", "last_ip": "10.1.0.3"}]   # stale, other VLAN
    active = [{"mac": "aa:00:00:00:00:01", "hostname": "phone", "ip": "10.0.0.11"}]
    assert build([], users, active).records == {"phone.internal": {"10.0.0.11"}}


def test_orphaned_proxmox_mac_in_unifi_is_ignored():
    users = [{"mac": "bc:24:11:00:00:99", "hostname": "nginxproxymanager", "last_ip": "10.1.0.20"},
             {"mac": "aa:00:00:00:00:01", "hostname": "pixel", "last_ip": "10.0.0.50"}]
    g = lxc(125, "caddy", [("net0", "bc:24:11:00:00:04", "services")], {"bc:24:11:00:00:04": ["10.1.0.20"]})
    assert set(build([g], users).records) == {"caddy.internal", "pixel.internal"}


def test_proxmox_nodes_named_from_cluster_and_offline_node_protected():
    users = [{"mac": "bc:24:11:00:00:aa", "hostname": "pve1", "last_ip": "10.2.0.1"}]  # node bridge: Proxmox MAC
    d = build([], users, nodes=[Node("pve1", "10.4.0.1", True), Node("pve2", "10.4.0.2", False)])
    assert d.records == {"pve1.internal": {"10.4.0.1"}, "pve2.internal": {"10.4.0.2"}}
    assert d.protected == {"pve2.internal"}


# ------------------------------------------------------------------------------------ sticky names

def test_unifi_hostname_is_sticky():
    d1 = build([], [{"mac": "aa:00:00:00:00:70", "hostname": "Kaiser", "last_ip": "10.0.0.70"}])
    d2 = build([], [{"mac": "aa:00:00:00:00:70", "hostname": None, "last_ip": "10.0.0.70"}], known=d1.known)
    assert d2.records == {"kaiser.internal": {"10.0.0.70"}}


def test_vm_hostname_is_sticky_when_agent_does_not_answer():
    def vm(hostname):
        return Guest(109, "qemu", "pve1", "hassio", "running", [Nic("net0", "02:00:00:00:00:01", "services")],
                     {"02:00:00:00:00:01": ["10.1.0.5"]}, hostname=hostname)
    d1 = build([vm("homeassistant")])
    d2 = build([vm(None)], known=d1.known)
    assert set(d2.records) == {"homeassistant.internal", "hassio.internal"}


def test_vm_never_seen_by_agent_uses_label_as_hostname():
    g = Guest(5, "qemu", "pve1", "router", "running", [Nic("net0", "02:00:00:00:00:05", "services")],
              {"02:00:00:00:00:05": ["10.1.0.55"]})
    assert build([g]).records == {"router.internal": {"10.1.0.55"}}


# -------------------------------------------------------------------- fallbacks and protection

def test_running_guest_without_live_ip_falls_back_to_unifi_and_is_protected():
    g = lxc(106, "grist", [("net0", "bc:24:11:00:00:06", "services")], None)
    users = [{"mac": "bc:24:11:00:00:06", "hostname": "grist", "last_ip": "10.1.0.100"}]
    d = build([g], users)
    assert d.records == {"grist.internal": {"10.1.0.100"}}
    assert "grist.internal" in d.protected and d.notes


def test_unreadable_config_protects_names():
    g = Guest(300, "lxc", "pve3", "offline", "unknown", None, hostname="offline")
    d = build([g])
    plan = make_plan({"offline.internal": {"10.1.0.7"}, "offline-default.internal": {"10.0.0.7"}}, d, {}, 0, CFG)
    assert plan.remove == [] and sorted(plan.held) == ["offline-default.internal", "offline.internal"]


def test_stopped_guest_name_enters_grace():
    g = lxc(5, "stopped", [("net0", "bc:24:11:00:00:07", "services")], None, status="stopped")
    users = [{"mac": "bc:24:11:00:00:07", "hostname": "stopped", "last_ip": "10.1.0.70"}]
    d = build([g], users)
    assert d.records == {}  # Unifi must not resurrect it either
    p = make_plan({"stopped.internal": {"10.1.0.70"}}, d, {}, now=0, cfg=CFG)
    assert p.remove == [] and "stopped.internal" in p.pending


def test_guest_ipv6_published_unless_disabled():
    g = lxc(7, "v6", [("net0", "bc:24:11:00:00:08", "services")],
            {"bc:24:11:00:00:08": ["10.1.0.8", "2001:db8::8", "fd00::8", "fe80::8"]})
    assert build([g]).records == {"v6.internal": {"10.1.0.8", "2001:db8::8"}}
    cfg4 = Config(**{**CFG.__dict__, "include_ipv6": False})
    assert build([g], cfg=cfg4).records == {"v6.internal": {"10.1.0.8"}}


# ------------------------------------------------------------------------------------------- plan

def test_missing_name_waits_for_grace_period_then_goes():
    d = Desired()
    d.add("keep.internal", {"10.0.0.1"}, "t")
    current = {"keep.internal": {"10.0.0.1"}, "gone.internal": {"10.0.0.2"}}

    p1 = make_plan(current, d, {}, now=1000, cfg=CFG)
    assert p1.remove == [] and p1.pending == {"gone.internal": 1000}

    p2 = make_plan(current, d, p1.pending, now=1000 + 899, cfg=CFG)
    assert p2.remove == []

    p3 = make_plan(current, d, p2.pending, now=1000 + 900, cfg=CFG)
    assert p3.remove == [("gone.internal", "10.0.0.2")] and p3.pending == {}


def test_name_that_comes_back_clears_pending():
    d = Desired()
    d.add("flaky.internal", {"10.0.0.3"}, "t")
    p = make_plan({"flaky.internal": {"10.0.0.3"}}, d, {"flaky.internal": 500}, now=10_000, cfg=CFG)
    assert p.remove == [] and p.add == [] and p.pending == {}


def test_ip_change_applies_immediately():
    d = Desired()
    d.add("svc.internal", {"10.0.0.9"}, "t")
    p = make_plan({"svc.internal": {"10.0.0.8"}}, d, {}, now=0, cfg=CFG)
    assert p.add == [("svc.internal", "10.0.0.9")] and p.remove == [("svc.internal", "10.0.0.8")]
