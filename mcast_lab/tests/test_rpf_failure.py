"""
A functional test to definitively prove that the kernel's RPF check
drops a multicast packet from an unroutable source.
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
def rpf_failure_env():
    """
    Sets up two namespaces connected by a veth pair for RPF failure testing.
    ns-source (veth-s, 192.168.1.1, unroutable_source) <---> (veth-r, 192.168.1.2) ns-router
    RPF is ENABLED in ns-router.
    """
    ns_source = "ns-rpf-source"
    ns_router = "ns-rpf-router"
    ip_source_veth = "192.168.1.1"
    ip_router_veth = "192.168.1.2"
    unroutable_source_ip = "10.0.0.100"  # This IP is not on the 192.168.1.0/24 subnet
    multicast_group = "224.1.1.1"
    multicast_port = 12345

    try:
        print("\n--- Setting up RPF failure test environment ---")
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
        # Add the unroutable source IP to veth-s (as a secondary IP) to allow sending from it
        run_ns_command(
            ns_source,
            ["ip", "addr", "add", f"{unroutable_source_ip}/32", "dev", "veth-s"],
        )

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
        # We explicitly set it to 1 for clarity, and ensure no route back to unroutable_source_ip
        run_ns_command(ns_router, ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"])
        run_ns_command(
            ns_router, ["sysctl", "-w", "net.ipv4.conf.default.rp_filter=1"]
        )
        run_ns_command(ns_router, ["sysctl", "-w", "net.ipv4.conf.veth-r.rp_filter=1"])

        # Ensure ns-source has no route back to unroutable_source_ip (it's a /32 on veth-s)
        # and ns-router has no route to unroutable_source_ip via veth-r
        # This is implicitly true as 10.0.0.100 is not in 192.168.1.0/24

        print("--- RPF failure test environment setup complete ---")
        yield (
            ns_source,
            ns_router,
            unroutable_source_ip,
            multicast_group,
            multicast_port,
            ip_router_veth,
        )
    finally:
        print("\n--- Tearing down RPF failure test environment ---")
        run_command(["ip", "netns", "del", ns_source], check=False)
        run_command(["ip", "netns", "del", ns_router], check=False)


# --- The RPF Failure Test ---


def test_multicast_rpf_drops_unroutable_source(rpf_failure_env):
    """
    Confirms that a multicast packet from an unroutable source is dropped
    by the kernel's RPF check after prerouting but before input.

    This test is now more rigorous: it includes a listener to ensure the
    *only* reason for a drop between prerouting and input is the RPF check.
    """
    print("\n--- Running multicast RPF drop test ---")
    (
        ns_source,
        ns_router,
        unroutable_source_ip,
        multicast_group,
        multicast_port,
        ip_router_veth,  # Get the router's IP for the listener
    ) = rpf_failure_env
    uid = uuid.uuid4().hex[:8]
    prerouting_trace_prefix = f"NFT_PREROUTING_RPF_{uid}"
    input_trace_prefix = f"NFT_INPUT_RPF_{uid}"

    # 1. Install nftables rules on prerouting and input hooks in ns-router.
    run_nft(
        ns_router,
        [
            "flush ruleset",
            "table ip filter {",
            "  chain prerouting {",
            "    type filter hook prerouting priority raw; policy accept;",
            f'    iif "veth-r" ip saddr {unroutable_source_ip} ip daddr {multicast_group} meta nftrace set 1',
            f'    log prefix "{prerouting_trace_prefix} " accept',
            "  }",
            "  chain input {",
            "    type filter hook input priority raw; policy accept;",
            f'    iif "veth-r" ip saddr {unroutable_source_ip} ip daddr {multicast_group} meta nftrace set 1',
            f'    log prefix "{input_trace_prefix} " accept',
            "  }",
            "}",
        ],
    )
    print("\n--- Prerouting and Input tracing rules installed in ns-router ---")

    # 2. Start listener and monitor.
    listen_proc = None
    monitor_proc = None
    try:
        # Start a Python listener in ns-router to correctly join the multicast group.
        # This eliminates the "no listener" ambiguity.
        listen_cmd = [
            "ip",
            "netns",
            "exec",
            ns_router,
            "python3",
            "mcast_lab/src/listen_multicast.py",
            ip_router_veth,
            multicast_group,
            str(multicast_port),
        ]
        listen_proc = subprocess.Popen(
            listen_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        time.sleep(0.5)

        # Start `nft monitor trace` in ns-router in the background.
        monitor_cmd = ["ip", "netns", "exec", ns_router, "nft", "monitor", "trace"]
        monitor_proc = subprocess.Popen(
            monitor_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        time.sleep(0.5)

        # 3. Send a single UDP multicast packet from ns-source with the unroutable source IP.
        print(
            f"\n--- Sending UDP multicast packet from {unroutable_source_ip} to {multicast_group}:{multicast_port} ---"
        )
        send_cmd = [
            "nc",
            "-u",
            "-s",
            unroutable_source_ip,  # Specify source IP
            "-w",
            "1",
            multicast_group,
            str(multicast_port),
        ]
        run_ns_command(ns_source, send_cmd, input="multicast_data\n", check=False)
        time.sleep(1)  # Give time for packet and trace events

        # 4. Collect output.
        monitor_proc.terminate()
        listen_proc.terminate()
        monitor_stdout, monitor_stderr = monitor_proc.communicate(timeout=5)
        listen_stdout, listen_stderr = listen_proc.communicate(timeout=5)

        print("\n--- nft monitor trace stdout (ns-router) ---")
        print(monitor_stdout)
        if monitor_stderr:
            print("\n--- nft monitor trace stderr (ns-router) ---")
            print(monitor_stderr)

        print("\n--- Listener stdout (ns-router) ---")
        print(listen_stdout)
        if listen_stderr:
            print("\n--- Listener stderr (ns-router) ---")
            print(listen_stderr)

        # 5. Assertions:
        # A. Verify prerouting hook was hit (packet arrived at Netfilter).
        assert (
            prerouting_trace_prefix in monitor_stdout
        ), "FAIL: PREROUTING hook trace was NOT found. Packet did not reach Netfilter."
        print("SUCCESS: PREROUTING hook trace was found.")

        # B. Verify input hook was NOT hit (packet was dropped by RPF).
        assert (
            input_trace_prefix not in monitor_stdout
        ), "FAIL: INPUT hook trace WAS found. Packet was NOT dropped by RPF as expected."
        print("SUCCESS: INPUT hook trace was NOT found, confirming RPF drop.")

        # C. Verify the listener received nothing.
        assert (
            "Received packet" not in listen_stdout
        ), "FAIL: Listener received a packet that should have been dropped."
        print("SUCCESS: Listener did not receive the packet, as expected.")

    finally:
        if monitor_proc and monitor_proc.poll() is None:
            monitor_proc.terminate()
        if listen_proc and listen_proc.poll() is None:
            listen_proc.terminate()
