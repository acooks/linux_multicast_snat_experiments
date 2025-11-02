"""
A functional test to definitively prove that a multicast packet from a
routable source passes the kernel's RPF check.
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
def rpf_pass_env():
    """
    Sets up two namespaces connected by a veth pair for RPF pass testing.
    ns-source (veth-s, 192.168.1.1) <---> (veth-r, 192.168.1.2) ns-router
    RPF is ENABLED in ns-router.
    """
    ns_source = "ns-rpf-pass-source"
    ns_router = "ns-rpf-pass-router"
    ip_source_veth = "192.168.1.1"
    ip_router_veth = "192.168.1.2"
    multicast_group = "224.1.1.1"
    multicast_port = 12345

    try:
        print("\n--- Setting up RPF pass test environment ---")
        # Clean up any previous setup
        run_command(["ip", "netns", "del", ns_source], check=False)
        run_command(["ip", "netns", "del", ns_router], check=False)

        # Create namespaces
        run_command(["ip", "netns", "add", ns_source])
        run_command(["ip", "netns", "add", ns_router])

        # Create veth pair and link to namespaces
        run_command(
            ["ip", "link", "add", "veth-s", "type", "veth", "peer", "name", "veth-r"]
        )
        run_command(["ip", "link", "set", "veth-s", "netns", ns_source])
        run_command(["ip", "link", "set", "veth-r", "netns", ns_router])

        # Configure interfaces in ns-source
        run_ns_command(
            ns_source, ["ip", "addr", "add", f"{ip_source_veth}/24", "dev", "veth-s"]
        )
        run_ns_command(ns_source, ["ip", "link", "set", "veth-s", "up"])
        run_ns_command(ns_source, ["ip", "link", "set", "lo", "up"])

        # Configure interfaces in ns-router
        run_ns_command(
            ns_router, ["ip", "addr", "add", f"{ip_router_veth}/24", "dev", "veth-r"]
        )
        run_ns_command(ns_router, ["ip", "link", "set", "veth-r", "up"])
        run_ns_command(ns_router, ["ip", "link", "set", "lo", "up"])

        # Enable multicast on veth interfaces
        run_ns_command(
            ns_source, ["ip", "link", "set", "dev", "veth-s", "multicast", "on"]
        )
        run_ns_command(
            ns_router, ["ip", "link", "set", "dev", "veth-r", "multicast", "on"]
        )

        # CRITICAL: Ensure RPF is ENABLED in ns-router (default is 1 for veth-r)
        run_ns_command(ns_router, ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"])
        run_ns_command(ns_router, ["sysctl", "-w", "net.ipv4.conf.default.rp_filter=1"])
        run_ns_command(ns_router, ["sysctl", "-w", "net.ipv4.conf.veth-r.rp_filter=1"])

        print("--- RPF pass test environment setup complete ---")
        yield ns_source, ns_router, ip_source_veth, ip_router_veth, multicast_group, multicast_port
    finally:
        print("\n--- Tearing down RPF pass test environment ---")
        run_command(["ip", "netns", "del", ns_source], check=False)
        run_command(["ip", "netns", "del", ns_router], check=False)


# --- The RPF Pass Test ---


def test_multicast_rpf_passes_routable_source(rpf_pass_env):
    """
    Confirms that a multicast packet from a routable source is NOT dropped
    by the kernel's RPF check.
    """
    print("\n--- Running multicast RPF pass test ---")
    (
        ns_source,
        ns_router,
        ip_source_veth,
        ip_router_veth,
        multicast_group,
        multicast_port,
    ) = rpf_pass_env
    uid = uuid.uuid4().hex[:8]
    prerouting_trace_prefix = f"NFT_PREROUTING_RPF_PASS_{uid}"
    input_trace_prefix = f"NFT_INPUT_RPF_PASS_{uid}"

    # 1. Install nftables rules on prerouting and input hooks in ns-router.
    run_nft(
        ns_router,
        [
            "flush ruleset",
            "table ip filter {",
            "  chain prerouting {",
            "    type filter hook prerouting priority raw; policy accept;",
            f'    iif "veth-r" ip saddr {ip_source_veth} ip daddr {multicast_group} meta nftrace set 1',
            f'    log prefix "{prerouting_trace_prefix} " accept',
            "  }",
            "  chain input {",
            "    type filter hook input priority raw; policy accept;",
            f'    iif "veth-r" ip saddr {ip_source_veth} ip daddr {multicast_group} meta nftrace set 1',
            f'    log prefix "{input_trace_prefix} " accept',
            "  }",
            "}",
        ],
    )
    print("\n--- Prerouting and Input tracing rules installed in ns-router ---")

    # 2. Start a Python listener in ns-router to correctly join the multicast group.
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
    time.sleep(0.5)

    # 3. Start `nft monitor trace` in ns-router in the background.
    monitor_cmd = ["ip", "netns", "exec", ns_router, "nft", "monitor", "trace"]
    monitor_proc = subprocess.Popen(
        monitor_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(0.5)

    # 4. Send a single UDP multicast packet from ns-source with the routable source IP.
    print(
        f"\n--- Sending UDP multicast packet from {ip_source_veth} to {multicast_group}:{multicast_port} ---"
    )
    send_cmd = [
        "nc",
        "-u",
        "-s",
        ip_source_veth,  # Specify source IP
        "-w",
        "1",
        multicast_group,
        str(multicast_port),
    ]
    run_ns_command(ns_source, send_cmd, input="multicast_data\n", check=False)
    time.sleep(1)  # Give time for packet and trace events

    # 5. Terminate processes and collect output.
    monitor_proc.terminate()
    listen_proc.terminate()
    monitor_stdout, monitor_stderr = monitor_proc.communicate(timeout=5)

    print("\n--- nft monitor trace stdout (ns-router) ---")
    print(monitor_stdout)
    if monitor_stderr:
        print("\n--- nft monitor trace stderr (ns-router) ---")
        print(monitor_stderr)

    # 5. Assertions:
    # A. Verify prerouting hook was hit.
    assert (
        prerouting_trace_prefix in monitor_stdout
    ), "FAIL: PREROUTING hook trace was NOT found."
    print("SUCCESS: PREROUTING hook trace was found.")

    # B. Verify input hook was also hit (packet was NOT dropped by RPF).
    assert (
        input_trace_prefix in monitor_stdout
    ), "FAIL: INPUT hook trace was NOT found. Packet was dropped by RPF unexpectedly."
    print("SUCCESS: INPUT hook trace was found, confirming RPF pass.")
