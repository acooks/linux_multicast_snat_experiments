"""
A functional test to definitively determine if nftables can SNAT a multicast
packet in the prerouting hook, thereby bypassing the kernel's RPF check.
"""

import pytest
import time
import subprocess
import uuid

# --- Helper Functions ---


def run_command(cmd, check=True, input=None, text=True):
    """Runs a command on the host."""
    print(f"[CMD] {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            check=check,
            capture_output=True,
            text=text,
            input=input,
            timeout=10,
        )
        return result.stdout, result.stderr
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"  [ERROR] Command failed: {e}")
        if e.stdout:
            print(f"  [STDOUT] {e.stdout}")
        if e.stderr:
            print(f"  [STDERR] {e.stderr}")
        if check:
            raise
        return e.stdout or "", e.stderr or ""


def run_ns_command(ns_name, cmd, check=True, input=None):
    """Runs a command inside a network namespace."""
    return run_command(["ip", "netns", "exec", ns_name] + cmd, check=check, input=input)


def run_nft(ns_name, commands):
    """Executes a list of nft commands in a namespace."""
    cmd_str = "\n".join(commands)
    run_ns_command(ns_name, ["nft", "-f", "-"], input=cmd_str, check=True)


# --- Test Fixture ---


@pytest.fixture
def multicast_snat_rpf_env():
    """
    Sets up two namespaces connected by a veth pair for multicast RPF testing.
    ns-source (veth-s, 192.168.1.1, unroutable_source) <---> (veth-r, 192.168.1.2) ns-router
    RPF is ENABLED in ns-router.
    """
    ns_source = "ns-snat-source"
    ns_router = "ns-snat-router"
    ip_source_veth = "192.168.1.1"
    ip_router_veth = "192.168.1.2"
    unroutable_source_ip = "10.0.0.100"
    routable_snat_ip = "192.168.1.2"
    multicast_group = "224.1.1.1"
    multicast_port = 12345

    try:
        print("\n--- Setting up multicast SNAT RPF test environment ---")
        run_command(["ip", "netns", "del", ns_source], check=False)
        run_command(["ip", "netns", "del", ns_router], check=False)
        run_command(["ip", "netns", "add", ns_source])
        run_command(["ip", "netns", "add", ns_router])
        run_command(
            ["ip", "link", "add", "veth-s", "type", "veth", "peer", "name", "veth-r"]
        )
        run_command(["ip", "link", "set", "veth-s", "netns", ns_source])
        run_command(["ip", "link", "set", "veth-r", "netns", ns_router])

        run_ns_command(
            ns_source, ["ip", "addr", "add", f"{ip_source_veth}/24", "dev", "veth-s"]
        )
        run_ns_command(ns_source, ["ip", "link", "set", "veth-s", "up"])
        run_ns_command(
            ns_source,
            ["ip", "addr", "add", f"{unroutable_source_ip}/32", "dev", "veth-s"],
        )

        run_ns_command(
            ns_router, ["ip", "addr", "add", f"{ip_router_veth}/24", "dev", "veth-r"]
        )
        run_ns_command(ns_router, ["ip", "link", "set", "veth-r", "up"])
        run_ns_command(ns_router, ["ip", "link", "set", "lo", "up"])

        run_ns_command(
            ns_source, ["ip", "link", "set", "dev", "veth-s", "multicast", "on"]
        )
        run_ns_command(
            ns_router, ["ip", "link", "set", "dev", "veth-r", "multicast", "on"]
        )

        run_ns_command(ns_router, ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"])
        run_ns_command(ns_router, ["sysctl", "-w", "net.ipv4.conf.veth-r.rp_filter=1"])

        print("--- Multicast SNAT RPF test environment setup complete ---")
        yield (
            ns_source,
            ns_router,
            unroutable_source_ip,
            routable_snat_ip,
            multicast_group,
            multicast_port,
            ip_router_veth,
        )
    finally:
        print("\n--- Tearing down multicast SNAT RPF test environment ---")
        run_command(["ip", "netns", "del", ns_source], check=False)
        run_command(["ip", "netns", "del", ns_router], check=False)


# --- The Final Experiment ---


def test_multicast_snat_bypasses_rpf(multicast_snat_rpf_env):
    """
    Tests if nftables SNAT in prerouting can modify a multicast packet's source
    address before RPF, allowing it to be forwarded.
    """
    print("\n--- Running multicast SNAT RPF bypass test ---")
    (
        ns_source,
        ns_router,
        unroutable_source_ip,
        routable_snat_ip,
        multicast_group,
        multicast_port,
        ip_router_veth,
    ) = multicast_snat_rpf_env
    uid = uuid.uuid4().hex[:8]
    filter_prerouting_prefix = f"NFT_FILTER_PREROUTING_{uid}"
    filter_input_prefix = f"NFT_FILTER_INPUT_{uid}"

    # 1. Install a multi-stage tracing ruleset.
    run_nft(
        ns_router,
        [
            "flush ruleset",
            "table ip nat {",
            "  chain prerouting {",
            "    type nat hook prerouting priority -150; policy accept;",
            f'    iif "veth-r" ip saddr {unroutable_source_ip} ip daddr {multicast_group} meta nftrace set 1 snat to {routable_snat_ip}',
            "  }",
            "}",
            "table ip filter {",
            "  chain prerouting {",
            "    type filter hook prerouting priority 0; policy accept;",
            f'    iif "veth-r" ip daddr {multicast_group} meta nftrace set 1 log prefix "{filter_prerouting_prefix} "',
            "  }",
            "  chain input {",
            "    type filter hook input priority 0; policy accept;",
            f'    iif "veth-r" ip daddr {multicast_group} meta nftrace set 1 log prefix "{filter_input_prefix} "',
            "  }",
            "}",
        ],
    )
    print("\n--- Multi-stage tracing ruleset installed in ns-router ---")

    # 2. Start listener and monitor.
    listen_cmd = [
        "ip",
        "netns",
        "exec",
        ns_router,
        "./listen_multicast.py",
        ip_router_veth,
        multicast_group,
        str(multicast_port),
    ]
    listen_proc = subprocess.Popen(
        listen_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    monitor_cmd = ["ip", "netns", "exec", ns_router, "nft", "monitor", "trace"]
    monitor_proc = subprocess.Popen(
        monitor_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(1)

    # 3. Send the unroutable multicast packet.
    print(f"\n--- Sending UDP multicast packet from {unroutable_source_ip} ---")
    send_cmd = [
        "nc",
        "-u",
        "-s",
        unroutable_source_ip,
        "-w",
        "1",
        multicast_group,
        str(multicast_port),
    ]
    run_ns_command(ns_source, send_cmd, input="multicast_data\n", check=False)
    time.sleep(1)

    # 4. Collect output.
    monitor_proc.terminate()
    listen_proc.terminate()
    monitor_stdout, _ = monitor_proc.communicate(timeout=5)

    print("\n--- nft monitor trace stdout (ns-router) ---")
    print(monitor_stdout)

    # 5. Assertions
    # A. Check that the packet, post-NAT, hits the filter prerouting hook.
    # The trace will show the *new* source IP.
    assert (
        filter_prerouting_prefix in monitor_stdout
    ), "FAIL: Filter prerouting hook was not hit post-NAT."
    assert (
        f"ip saddr {routable_snat_ip}" in monitor_stdout
    ), "FAIL: Packet source address was not translated in filter prerouting."
    print(
        "SUCCESS: Filter prerouting hook was hit post-NAT with the correct translated source IP."
    )

    # B. Check that the packet hits the input hook, proving it passed RPF.
    assert (
        filter_input_prefix in monitor_stdout
    ), "FAIL: Filter input hook was not hit. RPF bypass failed."
    print("SUCCESS: Filter input hook was hit, confirming RPF bypass.")
