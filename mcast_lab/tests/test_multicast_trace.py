"""
A diagnostic test to confirm that nftables tracing works for a simple
multicast packet from a routable source traversing a veth pair between two namespaces.
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
def two_ns_multicast_env():
    """
    Sets up two namespaces connected by a veth pair for multicast testing.
    ns-source (veth-s, 192.168.1.1) <---> (veth-r, 192.168.1.2) ns-router
    """
    ns_source = "ns-mcast-source"
    ns_router = "ns-mcast-router"
    ip_source = "192.168.1.1"
    ip_router = "192.168.1.2"
    multicast_group = "224.1.1.1"
    multicast_port = 12345

    try:
        print("\n--- Setting up two-namespace multicast environment ---")
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
            ns_source, ["ip", "addr", "add", f"{ip_source}/24", "dev", "veth-s"]
        )
        run_ns_command(ns_source, ["ip", "link", "set", "veth-s", "up"])
        run_ns_command(ns_source, ["ip", "link", "set", "lo", "up"])

        # Configure interfaces in ns-router
        run_ns_command(
            ns_router, ["ip", "addr", "add", f"{ip_router}/24", "dev", "veth-r"]
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

        # Add multicast route in ns-source (optional, but good practice for multicast)
        run_ns_command(
            ns_source, ["ip", "route", "add", multicast_group, "dev", "veth-s"]
        )

        # Disable RPF in both namespaces (crucial for multicast and asymmetric routing)
        for ns in [ns_source, ns_router]:
            for i in ["all", "default", "veth-s", "veth-r"]:
                try:
                    run_ns_command(
                        ns, ["sysctl", "-w", f"net.ipv4.conf.{i}.rp_filter=0"]
                    )
                except Exception:
                    pass  # Ignore if interface doesn't exist in the namespace

        print("--- Two-namespace multicast environment setup complete ---")
        yield ns_source, ns_router, ip_source, ip_router, multicast_group, multicast_port
    finally:
        print("\n--- Tearing down two-namespace multicast environment ---")
        run_command(["ip", "netns", "del", ns_source], check=False)
        run_command(["ip", "netns", "del", ns_router], check=False)


# --- The Multicast Tracing Test ---


def test_multicast_packet_is_traced(two_ns_multicast_env):
    """
    Confirms that a multicast packet sent from ns-source to ns-router
    hits the prerouting hook in ns-router and is traced.
    """
    print("\n--- Running multicast packet tracing test ---")
    ns_source, ns_router, ip_source, ip_router, multicast_group, multicast_port = (
        two_ns_multicast_env
    )
    uid = uuid.uuid4().hex[:8]
    prerouting_trace_prefix = f"NFT_PREROUTING_MCAST_{uid}"

    # 1. Install nftables rule on the ip family's prerouting hook in ns-router.
    run_nft(
        ns_router,
        [
            "flush ruleset",
            "table ip filter {",
            "  chain prerouting {",
            "    type filter hook prerouting priority raw; policy accept;",
            f'    iif "veth-r" ip daddr {multicast_group} meta nftrace set 1',
            f'    log prefix "{prerouting_trace_prefix} " accept',
            "  }",
            "}",
        ],
    )
    print("\n--- IP prerouting nftables rule installed in ns-router ---")

    # 2. Start `nft monitor trace` in ns-router in the background.
    monitor_cmd = ["ip", "netns", "exec", ns_router, "nft", "monitor", "trace"]
    monitor_proc = subprocess.Popen(
        monitor_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(0.5)

    # 3. Send a single UDP multicast packet from ns-source.
    print(
        f"\n--- Sending UDP multicast packet from {ip_source} to {multicast_group}:{multicast_port} ---"
    )
    send_cmd = [
        "nc",
        "-u",
        "-s",
        ip_source,  # Specify source IP
        "-w",
        "1",
        multicast_group,
        str(multicast_port),
    ]
    run_ns_command(ns_source, send_cmd, input="multicast_data\n", check=False)
    time.sleep(1)  # Give time for packet and trace events

    # 4. Terminate processes and collect output.
    monitor_proc.terminate()
    monitor_stdout, monitor_stderr = monitor_proc.communicate(timeout=5)

    print("\n--- nft monitor trace stdout (ns-router) ---")
    print(monitor_stdout)
    if monitor_stderr:
        print("\n--- nft monitor trace stderr (ns-router) ---")
        print(monitor_stderr)

    # 5. Assert that the prerouting log prefix appeared in the monitor's output.
    assert prerouting_trace_prefix in monitor_stdout, (
        "FAIL: IP PREROUTING hook trace was NOT found in ns-router. "
        "Multicast packet did not hit the expected Netfilter hook."
    )
    print("\nSUCCESS: IP PREROUTING hook trace was found in ns-router.")
