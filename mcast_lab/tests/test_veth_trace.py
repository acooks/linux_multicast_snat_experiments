"""
A diagnostic test to confirm that nftables tracing works for a simple
ping between two namespaces connected by a veth pair.
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
def two_ns_veth_env():
    """
    Sets up two namespaces connected by a veth pair.
    ns-source (veth-s, 192.168.1.1) <---> (veth-r, 192.168.1.2) ns-router
    """
    ns_source = "ns-source"
    ns_router = "ns-router"
    ip_source = "192.168.1.1"
    ip_router = "192.168.1.2"

    try:
        print("\n--- Setting up two-namespace veth environment ---")
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
            ns_source, ["ip", "addr", "add", f"{ip_source}/24", "dev", "veth-s"]
        )
        run_ns_command(ns_source, ["ip", "link", "set", "veth-s", "up"])
        run_ns_command(ns_source, ["ip", "link", "set", "lo", "up"])

        run_ns_command(
            ns_router, ["ip", "addr", "add", f"{ip_router}/24", "dev", "veth-r"]
        )
        run_ns_command(ns_router, ["ip", "link", "set", "veth-r", "up"])
        run_ns_command(ns_router, ["ip", "link", "set", "lo", "up"])

        # Disable RPF in both namespaces
        for ns in [ns_source, ns_router]:
            for i in ["all", "default", "veth-s", "veth-r"]:
                try:
                    run_ns_command(
                        ns, ["sysctl", "-w", f"net.ipv4.conf.{i}.rp_filter=0"]
                    )
                except Exception:
                    pass  # Ignore if interface doesn't exist in the namespace

        print("--- Two-namespace veth environment setup complete ---")
        yield ns_source, ns_router, ip_router
    finally:
        print("\n--- Tearing down two-namespace veth environment ---")
        run_command(["ip", "netns", "del", ns_source], check=False)
        run_command(["ip", "netns", "del", ns_router], check=False)


# --- The Veth Tracing Test ---


def test_ping_between_ns_is_traced(two_ns_veth_env):
    """
    Confirms that a ping from ns-source to ns-router hits the prerouting
    and input hooks in ns-router.
    """
    print("\n--- Running ping between namespaces tracing test ---")
    ns_source, ns_router, ip_router = two_ns_veth_env
    uid = uuid.uuid4().hex[:8]
    prerouting_prefix = f"NFT_PREROUTING_{uid}"
    input_prefix = f"NFT_INPUT_{uid}"

    # 1. Install nftables rules in ns-router.
    run_nft(
        ns_router,
        [
            "flush ruleset",
            "table ip filter {",
            "  chain prerouting {",
            "    type filter hook prerouting priority raw; policy accept;",
            '    iif "veth-r" meta nftrace set 1',
            f'    log prefix "{prerouting_prefix} " accept',
            "  }",
            "  chain input {",
            "    type filter hook input priority raw; policy accept;",
            '    iif "veth-r" meta nftrace set 1',
            f'    log prefix "{input_prefix} " accept',
            "  }",
            "}",
        ],
    )
    print("\n--- Tracing ruleset installed in ns-router ---")

    # 2. Start `nft monitor trace` in ns-router.
    monitor_cmd = ["ip", "netns", "exec", ns_router, "nft", "monitor", "trace"]
    monitor_proc = subprocess.Popen(
        monitor_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(0.5)

    # 3. Send a single ping from ns-source to ns-router.
    print(f"\n--- Sending ping from ns-source to {ip_router} ---")
    ping_cmd = ["ip", "netns", "exec", ns_source, "ping", "-c", "1", ip_router]
    ping_proc = subprocess.Popen(
        ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(1)

    # 4. Terminate processes and collect output.
    ping_proc.terminate()
    monitor_proc.terminate()
    monitor_stdout, _ = monitor_proc.communicate(timeout=5)
    ping_proc.communicate(timeout=5)

    print("\n--- nft monitor trace stdout (ns-router) ---")
    print(monitor_stdout)

    # 5. Assert that the expected log prefixes appeared in the monitor's output.
    assert (
        prerouting_prefix in monitor_stdout
    ), "FAIL: PREROUTING hook trace was not found."
    assert input_prefix in monitor_stdout, "FAIL: INPUT hook trace was not found."
    print("\nSUCCESS: Prerouting and input hook traces were found.")
