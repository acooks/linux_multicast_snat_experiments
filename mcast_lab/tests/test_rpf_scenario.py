# tests/test_rpf_scenario.py
import pytest
import subprocess
import os
import sys
import time
import signal
import json
import socket
import struct
import threading
from pyroute2 import IPDB, NetNS

# Mark all tests in this file as requiring root privileges
pytestmark = pytest.mark.skipif(
    os.geteuid() != 0, reason="RPF scenario tests require root privileges"
)

# --- Test Configuration ---
MCAST_GRP = "239.10.20.30"
MCAST_PORT = 12345
SOURCE_IP = "192.168.1.100"
ROUTER_LOOPBACK_IP = "172.16.0.1"
TEST_MESSAGE = b"RPF_TEST_PACKET"

# --- Helper Functions ---


def run_command(cmd, check=True):
    """Runs a command on the host."""
    print(f"[CMD] {" ".join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        if result.stdout.strip():
            print(f"  [STDOUT] {result.stdout.strip()}")
        if result.stderr.strip():
            print(f"  [STDERR] {result.stderr.strip()}")
        return result
    except subprocess.CalledProcessError as e:
        print(f"  [ERROR] Command failed: {e}")
        print(f"  [STDERR] {e.stderr}")
        raise


def run_ns_command(ns_name, cmd, check=True):
    """Runs a command inside a network namespace."""
    return run_command(["ip", "netns", "exec", ns_name] + cmd, check=check)


def set_sysctl(ns_name, key, value):
    """Sets a sysctl value inside a namespace."""
    run_ns_command(ns_name, ["sysctl", "-w", f"{key}={value}"])


def run_nft(ns_name, commands):
    """Runs nftables commands inside a namespace."""
    # Use -f - to read commands from stdin
    cmd_str = "\n".join(commands)
    full_cmd = ["ip", "netns", "exec", ns_name, "nft", "-f", "-"]
    print(f"[CMD] {" ".join(full_cmd)}")
    print(f"  [NFT] {cmd_str}")
    subprocess.run(full_cmd, input=cmd_str, text=True, check=True)


def run_cli(socket_path, command):
    """Helper to run the MFC CLI tool as a subprocess."""
    cli_cmd = [
        sys.executable,
        "-m",
        "src.mfc_cli",
        f"--socket-path={socket_path}",
    ] + command
    result = run_command(cli_cmd)
    return json.loads(result.stdout)


def receive_mcast(ns_name, group, port, queue):
    """
    Listens for a multicast packet in a namespace and puts the result in a queue.
    """
    try:
        with NetNS(ns_name):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(3.0)  # 3-second timeout
            sock.bind(("", port))

            mreq = struct.pack("4sl", socket.inet_aton(group), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            print(f"[{ns_name}] Listening for multicast on {group}:{port}...")
            data, addr = sock.recvfrom(1024)
            print(f"[{ns_name}] Received '{data.decode()}' from {addr}")
            queue.put((data, addr))
    except socket.timeout:
        print(f"[{ns_name}] Socket timeout, no packet received.")
        queue.put(None)
    except Exception as e:
        print(f"[{ns_name}] Receiver error: {e}")
        queue.put(None)


def start_tcpdump(ns_name, interface, output_file):
    """Starts tcpdump in a namespace, writing to a file."""
    cmd = [
        "ip",
        "netns",
        "exec",
        ns_name,
        "tcpdump",
        "-i",
        interface,
        "-n",
        "-v",
        "ip multicast",
        "-w",
        output_file,
    ]
    print(f"[TCPDUMP] Starting in {ns_name} on {interface}: {" ".join(cmd)}")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def stop_tcpdump(process, name=""):  # Added name for better logging
    """Stops a tcpdump process and prints its output."""
    if process and process.poll() is None:
        print(f"[TCPDUMP] Stopping {name}...")
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            print(f"[TCPDUMP] {name} did not terminate gracefully, killing...")
            process.kill()
            process.wait()
    stdout, stderr = process.communicate()
    if stdout:
        print(f"[TCPDUMP {name} STDOUT] {stdout.strip()}")
    if stderr:
        print(f"[TCPDUMP {name} STDERR] {stderr.strip()}")


# --- Pytest Fixture ---


@pytest.fixture
def rpf_test_env(tmp_path):
    """
    Sets up the multi-namespace environment for RPF testing.
    - ns-source: Unroutable source of multicast
    - ns-router: The device under test
    - ns-recv-20: A receiver on the 10.0.20.0/24 subnet
    - ns-recv-30: A receiver on the 10.0.30.0/24 subnet
    """
    namespaces = ["ns-source", "ns-router", "ns-recv-20", "ns-recv-30"]
    ipdb = IPDB()
    daemon_process = None
    tcpdump_procs = {}
    tcpdump_files = {}

    # --- Setup ---
    try:
        print("\n--- Setting up RPF test environment ---")

        # Pre-cleanup to ensure idempotency from previous failed runs
        for ifname in [
            "veth-s",
            "veth-r1",
            "veth-r20",
            "veth-c20",
            "veth-r30",
            "veth-c30",
        ]:
            if ifname in ipdb.interfaces:
                ipdb.interfaces[ifname].remove().commit()
        for ns in namespaces:
            if os.path.exists(f"/var/run/netns/{ns}"):
                run_command(["ip", "netns", "del", ns], check=False)

        for ns in namespaces:
            NetNS(ns)

        # Link source to router
        ipdb.create(kind="veth", ifname="veth-s", peer="veth-r1").commit()
        with ipdb.interfaces["veth-s"] as v:
            v.down()
            v.net_ns_fd = "ns-source"
        with ipdb.interfaces["veth-r1"] as v:
            v.down()
            v.net_ns_fd = "ns-router"

        # Link router to receiver 20
        ipdb.create(kind="veth", ifname="veth-r20", peer="veth-c20").commit()
        with ipdb.interfaces["veth-r20"] as v:
            v.down()
            v.net_ns_fd = "ns-router"
        with ipdb.interfaces["veth-c20"] as v:
            v.down()
            v.net_ns_fd = "ns-recv-20"

        # Link router to receiver 30
        ipdb.create(kind="veth", ifname="veth-r30", peer="veth-c30").commit()
        with ipdb.interfaces["veth-r30"] as v:
            v.down()
            v.net_ns_fd = "ns-router"
        with ipdb.interfaces["veth-c30"] as v:
            v.down()
            v.net_ns_fd = "ns-recv-30"

        # Configure IPs and links
        with IPDB(nl=NetNS("ns-source")) as db:
            with db.interfaces["veth-s"] as v:
                v.add_ip(f"{SOURCE_IP}/24")
                v.up()

        with IPDB(nl=NetNS("ns-router")) as db:
            db.interfaces["lo"].up()
            with db.interfaces["veth-r1"] as v:
                v.add_ip("192.168.1.1/24")
                v.up()
                v.multicast = 1
            with db.interfaces["veth-r20"] as v:
                v.add_ip("10.0.20.1/24")
                v.up()
                v.multicast = 1
            with db.interfaces["veth-r30"] as v:
                v.add_ip("10.0.30.1/24")
                v.up()
                v.multicast = 1

        with IPDB(nl=NetNS("ns-recv-20")) as db:
            with db.interfaces["veth-c20"] as v:
                v.add_ip("10.0.20.10/24")
                v.up()

        with IPDB(nl=NetNS("ns-recv-30")) as db:
            with db.interfaces["veth-c30"] as v:
                v.add_ip("10.0.30.10/24")
                v.up()

        # Enable IP forwarding and set default rp_filter on router
        set_sysctl("ns-router", "net.ipv4.ip_forward", "1")
        set_sysctl("ns-router", "net.ipv4.conf.all.rp_filter", "1")
        set_sysctl("ns-router", "net.ipv4.conf.default.rp_filter", "1")
        # *** NEW FIX: Enable conntrack for multicast ***
        set_sysctl("ns-router", "net.netfilter.nf_conntrack_mcast", "1")

        # Start tcpdump captures
        tcpdump_files["router_in"] = str(tmp_path / "router_in.pcap")
        tcpdump_procs["router_in"] = start_tcpdump(
            "ns-router", "veth-r1", tcpdump_files["router_in"]
        )

        tcpdump_files["router_out_20"] = str(tmp_path / "router_out_20.pcap")
        tcpdump_procs["router_out_20"] = start_tcpdump(
            "ns-router", "veth-r20", tcpdump_files["router_out_20"]
        )

        tcpdump_files["recv_20_in"] = str(tmp_path / "recv_20_in.pcap")
        tcpdump_procs["recv_20_in"] = start_tcpdump(
            "ns-recv-20", "veth-c20", tcpdump_files["recv_20_in"]
        )

        # Start the daemon
        socket_path = str(tmp_path / "mfc_daemon.sock")
        state_file = str(tmp_path / "mfc_state.json")
        daemon_cmd = [
            "ip",
            "netns",
            "exec",
            "ns-router",
            sys.executable,
            "-m",
            "src.daemon_main",
            "--socket-path",
            socket_path,
            "--state-file",
            state_file,
        ]
        daemon_process = subprocess.Popen(daemon_cmd, preexec_fn=os.setsid)
        time.sleep(1)
        assert daemon_process.poll() is None, "Daemon failed to start"

        print("--- Environment setup complete ---")
        yield {
            "socket_path": socket_path,
            "namespaces": namespaces,
            "tcpdump_files": tcpdump_files,
        }

    finally:
        # --- Teardown ---
        print("\n--- Tearing down RPF test environment ---")
        if daemon_process and daemon_process.poll() is None:
            os.killpg(os.getpgid(daemon_process.pid), signal.SIGTERM)
            try:
                daemon_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(daemon_process.pid), signal.SIGKILL)

        for name, proc in tcpdump_procs.items():
            stop_tcpdump(proc, name)

        if "ns-router" in namespaces and os.path.exists("/var/run/netns/ns-router"):
            print("\n--- Kernel Log from ns-router ---")
            run_command(["ip", "netns", "exec", "ns-router", "dmesg"], check=False)

        print("\n--- Analyzing TCPDUMP captures ---")
        for name, file_path in tcpdump_files.items():
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                print(f"\n--- Capture for {name} ({file_path}) ---")
                run_command(["tcpdump", "-r", file_path, "-n", "-v"], check=False)
            else:
                print(
                    f"\n--- Capture for {name} ({file_path}) is empty or does not exist ---"
                )

        for ns in namespaces:
            if os.path.exists(f"/var/run/netns/{ns}"):
                run_command(["ip", "netns", "del", ns], check=False)

        ipdb.release()


# --- Test Cases ---


def test_control_failure_with_rpf(rpf_test_env):
    """
    Experiment 3: The Control (Baseline Failure)
    Verifies that with default strict RPF, multicast from an unroutable
    source is dropped by the kernel.
    """
    socket_path = rpf_test_env["socket_path"]
    tcpdump_files = rpf_test_env["tcpdump_files"]

    print("\n--- EXPERIMENT 3: Testing Control Failure (RPF Enabled) ---")

    # 1. Add the original multicast route
    run_cli(
        socket_path,
        [
            "mfc",
            "add",
            "--source",
            SOURCE_IP,
            "--group",
            MCAST_GRP,
            "--iif",
            "veth-r1",
            "--oifs",
            "veth-r20,veth-r30",
        ],
    )

    # 2. Start receivers
    from queue import Queue

    q20, q30 = Queue(), Queue()
    recv20 = threading.Thread(
        target=receive_mcast, args=("ns-recv-20", MCAST_GRP, MCAST_PORT, q20)
    )
    recv30 = threading.Thread(
        target=receive_mcast, args=("ns-recv-30", MCAST_GRP, MCAST_PORT, q30)
    )
    recv20.start()
    recv30.start()
    time.sleep(0.5)  # Let receivers start listening

    # 3. Send multicast packet from the unroutable source
    p = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            "ns-source",
            "socat",
            "-u",
            "-",
            f"UDP4-DATAGRAM:{MCAST_GRP}:{MCAST_PORT},ip-multicast-if=veth-s",
        ],
        stdin=subprocess.PIPE,
    )
    p.communicate(input=TEST_MESSAGE)

    # 4. Verify failure (no packets received)
    recv20.join()
    recv30.join()

    assert q20.get() is None, "Packet should NOT have been received in ns-recv-20"
    assert q30.get() is None, "Packet should NOT have been received in ns-recv-30"
    print("--- VERIFIED: Packets were dropped as expected due to RPF. ---")


def test_postrouting_snat_solution(rpf_test_env):
    """
    Experiment 1: Test Hypothesis A (POSTROUTING Solution)
    Verifies that with rp_filter=0 on ingress and a POSTROUTING SNAT rule,
    the stream is forwarded correctly to multiple egress subnets.
    """
    socket_path = rpf_test_env["socket_path"]
    tcpdump_files = rpf_test_env["tcpdump_files"]

    print("\n--- EXPERIMENT 1: Testing POSTROUTING SNAT Solution ---")

    # 1. Disable rp_filter on the ingress interface
    set_sysctl("ns-router", "net.ipv4.conf.veth-r1.rp_filter", "0")

    # 2. Install nftables rules for POSTROUTING mangle
    run_nft(
        "ns-router",
        [
            "add table ip mangle",
            "add chain ip mangle postrouting { type filter hook postrouting priority 100; }",
            f"add rule ip mangle postrouting ip saddr {SOURCE_IP} ip daddr {MCAST_GRP} oifname veth-r20 ip saddr set 10.0.20.1",
            f"add rule ip mangle postrouting ip saddr {SOURCE_IP} ip daddr {MCAST_GRP} oifname veth-r30 ip saddr set 10.0.30.1",
        ],
    )
    time.sleep(1)  # Give nftables time to propagate
    run_ns_command("ns-router", ["nft", "list", "ruleset"])

    # 3. Add the multicast route for the ORIGINAL source
    run_cli(
        socket_path,
        [
            "mfc",
            "add",
            "--source",
            SOURCE_IP,
            "--group",
            MCAST_GRP,
            "--iif",
            "veth-r1",
            "--oifs",
            "veth-r20,veth-r30",
        ],
    )
    run_ns_command("ns-router", ["ip", "mroute", "show"])

    # 4. Start receivers
    from queue import Queue

    q20, q30 = Queue(), Queue()
    recv20 = threading.Thread(
        target=receive_mcast, args=("ns-recv-20", MCAST_GRP, MCAST_PORT, q20)
    )
    recv30 = threading.Thread(
        target=receive_mcast, args=("ns-recv-30", MCAST_GRP, MCAST_PORT, q30)
    )
    recv20.start()
    recv30.start()
    time.sleep(0.5)

    # 5. Send multicast packet
    p = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            "ns-source",
            "socat",
            "-u",
            "-",
            f"UDP4-DATAGRAM:{MCAST_GRP}:{MCAST_PORT},ip-multicast-if=veth-s",
        ],
        stdin=subprocess.PIPE,
    )
    p.communicate(input=TEST_MESSAGE)

    # 6. Verify success and correct source IPs
    recv20.join()
    recv30.join()

    result20 = q20.get()
    result30 = q30.get()

    assert result20 is not None, "Packet was not received in ns-recv-20"
    assert result20[0] == TEST_MESSAGE
    assert result20[1][0] == "10.0.20.1", "Source IP in ns-recv-20 is incorrect"

    assert result30 is not None, "Packet was not received in ns-recv-30"
    assert result30[0] == TEST_MESSAGE
    assert result30[1][0] == "10.0.30.1", "Source IP in ns-recv-30 is incorrect"
    print("--- VERIFIED: POSTROUTING solution works as expected. ---")


def test_prerouting_loopback_snat_solution(rpf_test_env):
    """
    Experiment 2: Test Hypothesis B (PREROUTING Loopback Solution)
    Verifies that with rp_filter=1 and a PREROUTING SNAT to a loopback IP,
    the stream is forwarded correctly.
    """
    socket_path = rpf_test_env["socket_path"]
    tcpdump_files = rpf_test_env["tcpdump_files"]

    print("\n--- EXPERIMENT 2: Testing PREROUTING Loopback SNAT Solution ---")

    # 1. Configure loopback on router and add routes in receivers
    run_ns_command(
        "ns-router", ["ip", "addr", "add", f"{ROUTER_LOOPBACK_IP}/32", "dev", "lo"]
    )
    run_ns_command(
        "ns-recv-20", ["ip", "route", "add", ROUTER_LOOPBACK_IP, "via", "10.0.20.1"]
    )
    run_ns_command(
        "ns-recv-30", ["ip", "route", "add", ROUTER_LOOPBACK_IP, "via", "10.0.30.1"]
    )

    # 2. Install nftables rule for INGRESS mangle with logging
    log_prefix = "'[NFT-INGRESS-MATCH] '"
    run_nft(
        "ns-router",
        [
            "add table netdev mangle",
            "add chain netdev mangle ingress { type filter hook ingress device veth-r1 priority -500; }",
            f"add rule netdev mangle ingress ip saddr {SOURCE_IP} ip daddr {MCAST_GRP} log prefix {log_prefix} group 0",
            f"add rule netdev mangle ingress ip saddr {SOURCE_IP} ip daddr {MCAST_GRP} ip saddr set {ROUTER_LOOPBACK_IP}",
        ],
    )
    time.sleep(1)  # Give nftables time to propagate
    run_ns_command("ns-router", ["nft", "list", "ruleset"])

    # 3. Add the multicast route for the TRANSLATED source
    run_cli(
        socket_path,
        [
            "mfc",
            "add",
            "--source",
            ROUTER_LOOPBACK_IP,
            "--group",
            MCAST_GRP,
            "--iif",
            "veth-r1",
            "--oifs",
            "veth-r20,veth-r30",
        ],
    )
    run_ns_command("ns-router", ["ip", "mroute", "show"])

    # 4. Start receivers
    from queue import Queue

    q20, q30 = Queue(), Queue()
    recv20 = threading.Thread(
        target=receive_mcast, args=("ns-recv-20", MCAST_GRP, MCAST_PORT, q20)
    )
    recv30 = threading.Thread(
        target=receive_mcast, args=("ns-recv-30", MCAST_GRP, MCAST_PORT, q30)
    )
    recv20.start()
    recv30.start()
    time.sleep(0.5)

    # 5. Send multicast packet
    p = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            "ns-source",
            "socat",
            "-u",
            "-",
            f"UDP4-DATAGRAM:{MCAST_GRP}:{MCAST_PORT},ip-multicast-if=veth-s",
        ],
        stdin=subprocess.PIPE,
    )
    p.communicate(input=TEST_MESSAGE)

    # 6. Verify success and correct source IPs
    recv20.join()
    recv30.join()

    result20 = q20.get()
    result30 = q30.get()

    assert result20 is not None, "Packet was not received in ns-recv-20"
    assert result20[0] == TEST_MESSAGE
    assert result20[1][0] == ROUTER_LOOPBACK_IP, "Source IP in ns-recv-20 is incorrect"

    assert result30 is not None, "Packet was not received in ns-recv-30"
    assert result30[0] == TEST_MESSAGE
    assert result30[1][0] == ROUTER_LOOPBACK_IP, "Source IP in ns-recv-30 is incorrect"
    print("--- VERIFIED: PREROUTING solution works as expected. ---")
