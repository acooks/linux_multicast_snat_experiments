

import os
import subprocess
import sys
import time
import traceback


def log(message, file=None):
    """Helper for logging with a clear prefix."""
    print(f"[Orchestrator] {message}", flush=True, file=file)


def run_command(command, check=True):
    """Helper to run a command on the host system with sudo."""
    full_cmd = ["sudo"] + command
    log(f"Running on host: {' '.join(full_cmd)}")
    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=check)
        if result.stdout.strip():
            log(f"  --> stdout: {result.stdout.strip()}")
        if result.stderr.strip():
            log(f"  --> stderr: {result.stderr.strip()}", file=sys.stderr)
        return result.stdout
    except subprocess.CalledProcessError as e:
        log(f"Command failed: {e}", file=sys.stderr)
        if e.stdout:
            log(f"Stdout:\n{e.stdout}", file=sys.stderr)
        if e.stderr:
            log(f"Stderr:\n{e.stderr}", file=sys.stderr)
        raise


def run_ns_command(ns_name, command, check=True, env=None):
    """Helper to run a command inside a namespace."""
    full_cmd = ["sudo", "ip", "netns", "exec", ns_name]
    if env and "PYTHONPATH" in env:
        full_cmd.extend(["env", f"PYTHONPATH={env['PYTHONPATH']}"])
    full_cmd.extend(command)
    log(f"Running in {ns_name}: {' '.join(command)}")
    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=check, env=env)
        # Print stdout/stderr only if they contain something
        if result.stdout.strip():
            log(f"  --> stdout: {result.stdout.strip()}")
        if result.stderr.strip():
            log(f"  --> stderr: {result.stderr.strip()}", file=sys.stderr)
        return result.stdout
    except subprocess.CalledProcessError as e:
        log(f"Command failed: {e}", file=sys.stderr)
        if e.stdout:
            log(f"Stdout:\n{e.stdout}", file=sys.stderr)
        if e.stderr:
            log(f"Stderr:\n{e.stderr}", file=sys.stderr)
        raise


def main():
    # --- Configuration ---
    ns_name = "mfc-lab"
    veth_in_host, veth_in_peer = "veth-in-h", "veth-in-p"
    veth_out_host, veth_out_peer = "veth-out-h", "veth-out-p"

    try:
        # --- [Setup] Phase ---
        log("--- [Setup] Phase ---")
        run_command(["ip", "netns", "add", ns_name])
        log(f"Created namespace '{ns_name}'.")

        run_command(["ip", "link", "add", veth_in_host, "type", "veth", "peer", "name", veth_in_peer])
        log(f"Created veth pair {veth_in_host} <--> {veth_in_peer}.")
        run_command(["ip", "link", "add", veth_out_host, "type", "veth", "peer", "name", veth_out_peer])
        log(f"Created veth pair {veth_out_host} <--> {veth_out_peer}.")

        run_command(["ip", "link", "set", veth_in_peer, "netns", ns_name])
        run_command(["ip", "link", "set", veth_out_peer, "netns", ns_name])
        log(f"Moved peer interfaces into '{ns_name}'.")

        run_ns_command(ns_name, ["ip", "addr", "add", "10.0.1.1/24", "dev", veth_in_peer])
        run_ns_command(ns_name, ["ip", "link", "set", veth_in_peer, "up"])
        run_ns_command(ns_name, ["ip", "link", "set", veth_in_peer, "multicast", "on"])
        
        run_ns_command(ns_name, ["ip", "addr", "add", "10.0.2.1/24", "dev", veth_out_peer])
        run_ns_command(ns_name, ["ip", "link", "set", veth_out_peer, "up"])
        run_ns_command(ns_name, ["ip", "link", "set", veth_out_peer, "multicast", "on"])

        # Get interface indices
        ifindex_in_str = run_ns_command(ns_name, ["cat", f"/sys/class/net/{veth_in_peer}/ifindex"])
        ifindex_out_str = run_ns_command(ns_name, ["cat", f"/sys/class/net/{veth_out_peer}/ifindex"])
        ifindex_in = int(ifindex_in_str.strip())
        ifindex_out = int(ifindex_out_str.strip())

        log(
            f"Configured interfaces inside namespace: '{veth_in_peer}' (idx {ifindex_in}) and '{veth_out_peer}' (idx {ifindex_out})."
        )

        # --- [Execution] Phase ---
        log("\n--- [Execution] Phase ---")
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        vendored_pymfcd_path = os.path.join(script_dir, "pymfcd_vendored")
        
        env = os.environ.copy()
        env["PYTHONPATH"] = vendored_pymfcd_path

        python_executable = sys.executable

        # Start the pymfcd daemon in the background
        log("Starting pymfcd daemon...")
        daemon_cmd = [
            "env", f"PYTHONPATH={env['PYTHONPATH']}",
            python_executable, "-m", "pymfcd.daemon_main"
        ]
        daemon_proc = subprocess.Popen(
            ["sudo", "ip", "netns", "exec", ns_name] + daemon_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(1) # Give the daemon a moment to start
        if daemon_proc.poll() is not None:
            log("Daemon failed to start.", file=sys.stderr)
            stdout, stderr = daemon_proc.communicate()
            if stdout:
                log(f"Daemon stdout:\n{stdout}", file=sys.stderr)
            if stderr:
                log(f"Daemon stderr:\n{stderr}", file=sys.stderr)
            raise RuntimeError("Failed to start pymfcd daemon.")
        log(f"Daemon started with PID {daemon_proc.pid}.")

        run_ns_command(ns_name, [
            python_executable, "-m", "pymfcd.mfc_cli",
            "mfc", "add",
            "--iif", veth_in_peer,
            "--group", "239.1.2.3",
            "--source", "10.0.1.10",
            "--oifs", veth_out_peer
        ], env=env)


        # --- [Verification: After] Phase ---
        log("\n--- [Verification: After] Phase ---")
        log("Checking kernel state after daemon initialization...")
        run_ns_command(ns_name, ["cat", "/proc/net/ip_mr_vif"])
        mroute_output = run_ns_command(ns_name, ["ip", "mroute", "show"])

        if (
            "(10.0.1.10,239.1.2.3)" in mroute_output
            and f"Iif: {veth_in_peer}" in mroute_output
        ):
            log(
                ">>> VERIFICATION SUCCESS: The multicast route was found in the kernel. <<<"
            )
        else:
            log(
                ">>> VERIFICATION FAILED: The multicast route was NOT found. <<<",
                file=sys.stderr,
            )
            raise RuntimeError("MFC entry verification failed.")

    except Exception:
        log("\n--- [Error] An unexpected error occurred. ---", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

    finally:
        # --- [Cleanup] Phase ---
        log("\n--- [Cleanup] Phase ---")
        if 'daemon_proc' in locals() and daemon_proc.poll() is None:
            daemon_proc.terminate()
            daemon_proc.wait()
            log("Daemon terminated.")
        # Check if the namespace exists before trying to delete it
        result = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
        if ns_name in result.stdout:
            run_command(["ip", "netns", "del", ns_name], check=False)
            log(f"Namespace '{ns_name}' removed.")
        log("Cleanup complete.")



if __name__ == "__main__":
    """
    Main function to set up the environment, run the experiment, and clean up.
    """
    main()
