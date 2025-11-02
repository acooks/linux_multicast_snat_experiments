"""
A foundational diagnostic test to provide positive confirmation that nftables
event monitoring works correctly for a simple, local packet loopback
using a single namespace, single dummy interface, and a ping to itself.
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
def single_ip_dummy_env():
    """
    Sets up a single namespace with a single dummy interface and IP address.
    """
    namespace = "ns-simple"
    dummy_ip = "192.168.100.1"
    try:
        print("\n--- Setting up single-IP dummy environment ---")
        run_command(["ip", "netns", "del", namespace], check=False)
        run_command(["ip", "netns", "add", namespace])
        run_ns_command(namespace, ["ip", "link", "add", "dummy0", "type", "dummy"])
        run_ns_command(
            namespace, ["ip", "addr", "add", f"{dummy_ip}/24", "dev", "dummy0"]
        )
        run_ns_command(namespace, ["ip", "link", "set", "dummy0", "up"])
        run_ns_command(namespace, ["ip", "link", "set", "lo", "up"])

        # Disable RPF to prevent any unforeseen drops, even for local delivery.
        for i in ["all", "default", "dummy0"]:
            run_ns_command(
                namespace, ["sysctl", "-w", f"net.ipv4.conf.{i}.rp_filter=0"]
            )

        print("--- Single-IP dummy environment setup complete ---")
        yield namespace, dummy_ip
    finally:
        print("\n--- Tearing down single-IP dummy environment ---")
        run_command(["ip", "netns", "del", namespace], check=False)


# --- The Foundational Test ---


def test_single_ip_dummy_ping_is_traced(single_ip_dummy_env):
    """
    Confirms that `nft monitor trace` correctly captures trace events for a simple
    ping to a local dummy interface, hitting all expected netfilter hooks.
    """
    print("\n--- Running single-IP dummy ping tracing test ---")
    namespace, dummy_ip = single_ip_dummy_env
    uid = uuid.uuid4().hex[:8]
    output_prefix = f"nft_test_output {uid}"
    prerouting_prefix = f"nft_test_prerouting {uid}"
    postrouting_prefix = f"nft_test_postrouting {uid}"
    input_prefix = f"nft_test_input {uid}"

    # 1. Install nftables rules with tracing and logging on multiple hooks.
    # The rules are based on the user-provided @nft-dummy-ruleset.txt
    run_nft(
        namespace,
        [
            "flush ruleset",
            "table ip filter {",
            "  chain output {",
            "    type filter hook output priority raw; policy accept;",
            f'    oif "lo" ip saddr {dummy_ip} meta nftrace set 1',
            f'    log prefix "{output_prefix} " accept',
            "  }",
            "  chain prerouting {",
            "    type filter hook prerouting priority raw; policy accept;",
            f'    iif "lo" ip saddr {dummy_ip} meta nftrace set 1',
            f'    log prefix "{prerouting_prefix} " accept',
            "  }",
            "  chain postrouting {",
            "    type filter hook postrouting priority raw; policy accept;",
            f'    oif "lo" ip saddr {dummy_ip} meta nftrace set 1',
            f'    log prefix "{postrouting_prefix} " accept',
            "  }",
            "  chain input {",
            "    type filter hook input priority raw; policy accept;",
            f'    iif "lo" ip saddr {dummy_ip} meta nftrace set 1',
            f'    log prefix "{input_prefix} " accept',
            "  }",
            "}",
        ],
    )
    print("\n--- Multi-hook nftables tracing ruleset installed ---")

    # 2. Start `nft monitor trace` in the background.
    monitor_cmd = ["ip", "netns", "exec", namespace, "nft", "monitor", "trace"]
    monitor_proc = subprocess.Popen(
        monitor_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(0.5)

    # 3. Send a single ping to the dummy interface.
    # We run ping in the background and don't check its return code,
    # as the goal is to observe nftables tracing, not ping success.
    print(f"\n--- Sending control ping to {dummy_ip} ---")
    ping_cmd = ["ip", "netns", "exec", namespace, "ping", "-c", "1", dummy_ip]
    ping_proc = subprocess.Popen(
        ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(1)  # Give time for ping and trace events

    # 4. Terminate processes and collect output.
    ping_proc.terminate()
    monitor_proc.terminate()
    monitor_stdout, monitor_stderr = monitor_proc.communicate(timeout=5)
    ping_stdout, ping_stderr = ping_proc.communicate(timeout=5)

    print("\n--- nft monitor trace stdout ---")
    print(monitor_stdout)
    if monitor_stderr:
        print("\n--- nft monitor trace stderr ---")
        print(monitor_stderr)
    print("\n--- ping stdout ---")
    print(ping_stdout)
    if ping_stderr:
        print("\n--- ping stderr ---")
        print(ping_stderr)

    # 5. Assert that all expected log prefixes appeared in the monitor's output.
    # We expect output, prerouting, postrouting, and input for a local ping.
    assert output_prefix in monitor_stdout, "FAIL: OUTPUT hook trace/log was not found."
    assert (
        prerouting_prefix in monitor_stdout
    ), "FAIL: PREROUTING hook trace/log was not found."
    assert (
        postrouting_prefix in monitor_stdout
    ), "FAIL: POSTROUTING hook trace/log was not found."
    assert input_prefix in monitor_stdout, "FAIL: INPUT hook trace/log was not found."
    print(
        "\nSUCCESS: All expected hook traces/logs (output, prerouting, postrouting, input) were found."
    )
