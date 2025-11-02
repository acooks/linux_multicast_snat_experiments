# A Sysadmin's Guide to Debugging Packet Drops on Linux

## Introduction

The "disappearing packet" is a classic and maddening problem. A packet leaves host A, `tcpdump` on host B confirms its arrival on the wire, yet the application remains silent. The packet has entered the kernel and vanished. For a sysadmin or network engineer, this is where the real work begins.

This is not a high-level overview. This is a deep dive into the methodologies and tools available to trace a packet's journey through the Linux kernel and pinpoint the exact location and reason for its demise. We will move from coarse, high-level checks to the surgical precision of kernel-level tracing, explaining the mechanism of each tool and when to use it.

---

## The Ingress Path: A Kernel Map

Before we use any tools, we must have a map of the territory. The journey of an incoming packet from the wire to a socket is a multi-stage process. A simplified but functionally accurate model for the IPv4 path is as follows:

1.  **`netif_receive_skb()`:** The driver passes the packet to the generic network layer. `tcpdump` gets its copy here.
2.  **`ip_rcv_core()`:** The packet enters the IP stack. Basic header sanity checks are performed. A check for `PACKET_OTHERHOST` can cause a drop here.
3.  **`NF_INET_PRE_ROUTING` Hook:** The packet is passed to Netfilter. `nftrace` begins here. `raw`, `mangle`, and `nat` `prerouting` rules are processed.
4.  **`ip_rcv_finish()`:** After Netfilter, the routing decision is made. The **unicast RPF check** is performed as part of the FIB lookup.
5.  **`ip_mr_input()`:** If the packet is multicast and a route exists, the **multicast RPF check** is performed here. This is a separate check from the unicast one and is not affected by the `rp_filter` sysctl.
6.  **`NF_INET_LOCAL_IN` / `NF_INET_FORWARD` Hooks:** The packet continues through Netfilter's `input` or `forward` chains.
7.  **Socket Delivery:** The packet is delivered to a local socket.

Our goal is to use the right tool to see how far along this path our packet gets.

---

## The Toolkit: From Coarse to Fine-Grained

### Level 1: `tcpdump` - The Arrival Confirmation

`tcpdump` is the first and most important diagnostic. It tells you if the problem is on the host or on the network.

*   **Mechanism:** `tcpdump` uses a low-level `AF_PACKET` socket, which receives a copy of the packet directly from `netif_receive_skb()`. It sees the packet almost exactly as it came off the wire, before most of the kernel's protocol logic has a chance to inspect or drop it.
*   **Usage:**
    ```sh
    # Be specific. Use -n to prevent DNS lookups, -i for the interface,
    # and a filter to reduce noise. -c limits the count.
    sudo tcpdump -n -i eth0 -c 1 'host 192.168.1.10 and port 80'
    ```
*   **Interpretation:**
    *   **Packet Seen:** The packet has successfully traversed the network and been received by the kernel driver. The problem is on this host.
    *   **Packet NOT Seen:** The problem is not on this host. The packet was dropped by an upstream switch, router, or firewall, or a cloud provider's security group. **Stop debugging the host.**

### Level 2: Netfilter Tracing - The Firewall Interrogation

If `tcpdump` sees the packet, the next most likely culprit is the firewall. Netfilter's built-in tracing is the definitive tool for this.

*   **Mechanism:** `nftrace` (for `nftables`) and the `TRACE` target (for `iptables`) are kernel features that instruct Netfilter to log every single step of a packet's journey through all registered tables and chains. When a packet is traced, the kernel emits detailed log events about which rule it's being evaluated against and what the verdict is.
*   **Usage (`nftables`):**
    1.  Create a dedicated table and chain for tracing rules. The priority (`-400`) ensures it runs before any other `prerouting` chains.
        ```sh
        sudo nft add table inet packet_trace
        sudo nft add chain inet packet_trace trace_hook { type filter hook prerouting priority raw - 10 \; }
        ```
    2.  Add a rule to match the specific traffic you want to trace and enable the `nftrace` bit.
        ```sh
        sudo nft add rule inet packet_trace trace_hook ip saddr 192.168.1.10 tcp dport 80 meta nftrace set 1
        ```
    3.  Monitor the live trace events.
        ```sh
        sudo nft monitor trace
        ```
*   **Interpretation:** The output is a verbose, real-time log. You will see the packet enter each chain (`raw prerouting`, `mangle prerouting`, `nat prerouting`, etc.) and see each rule being evaluated until one terminates the process (e.g., with a `drop` verdict). This removes all guesswork about your firewall's logic.
    ```
trace id 1a2b3c4d inet packet_trace trace_hook packet: iif "eth0" ip saddr 192.168.1.10 ip daddr 192.168.1.20 ...
trace id 1a2b3c4d inet filter input rule 5 drop
```
    This output would definitively prove the packet was dropped by rule 5 in the `filter` table's `input` chain.

> **Warning: `veth`, Bridges, and the Two Netfilters**
>
> Be aware that Linux has two parallel Netfilter hook systems: one for IP (Layer 3) and one for bridges (Layer 2). Traffic between `veth` peers in separate network namespaces is often handled by the kernel in a way that is analogous to being forwarded by a Layer 2 bridge.
>
> This means the packet **bypasses the IP-level `prerouting` hook entirely**, rendering `nftrace` blind to this traffic. If you `tcpdump` a packet on a `veth` interface but `nftrace` remains silent, you are observing this mechanism. In these advanced container and namespace scenarios, you must use a lower-level tool like **`eBPF`** to trace the packet's true path.

### Level 3: `dropwatch` - The Kernel's Dropped Packet Accountant

If `tcpdump` sees the packet but `nftrace` is silent, you are in the "pre-Netfilter dark zone." The packet was dropped by `ip_rcv()` or a related function. `dropwatch` is the ideal tool for this scenario.

*   **Mechanism:** `dropwatch` attaches a kernel probe to the `kfree_skb` function. This is the generic, low-level function the kernel calls whenever it needs to free an `sk_buff`, which is the functional equivalent of dropping a packet. `dropwatch` listens for these events and records the memory location (the instruction pointer) of the code that called `kfree_skb`.
*   **Usage:**
    ```sh
    # Start dropwatch and tell it to translate memory addresses to kernel function names.
    sudo dropwatch -l kas
    ```
    Now, send your traffic. `dropwatch` will print a summary when it detects drops.
*   **Interpretation:** The output is concise and powerful.
    ```
    1 drops at ip_rcv+25b (0xffffffff817c847b)
    ```
    This tells you that one packet was dropped by a function call inside the `ip_rcv` function. This immediately narrows your search. You now know the drop is happening during initial IP validation. This result, combined with the knowledge that unicast RPF is enforced here, provides a very strong clue.

### Level 4: eBPF - The Ultimate Kernel Tracing Scalpel

For the most complex cases, or when you need more context than `dropwatch` can provide, eBPF is the ultimate tool. Using a framework like `bcc` (BPF Compiler Collection), you write Python scripts to deploy custom C tracing code directly into the live kernel.

*   **Mechanism:** eBPF allows you to attach probes (`kprobes`) to the entry and exit of almost any non-inlined kernel function. These probes can access function arguments (like the `sk_buff`), record data to maps, and send events to userspace. The most powerful technique is to trace `kfree_skb` and capture a full kernel stack trace at the moment of the drop.
*   **Usage:** The following `bcc` Python script is a robust tool for tracing a specific packet and finding out who dropped it.

    ```python
    #!/usr/bin/python3
    #
    # trace_drop.py: Trace a packet by IP and find the kernel drop location.
    #
    # USAGE: sudo ./trace_drop.py --saddr 192.168.1.10 --daddr 10.0.0.5
    
    import argparse
    from bcc import BPF
    import socket
    import struct
    
    # Argument parsing
    parser = argparse.ArgumentParser(description="Trace packet drops by source/dest IP")
    parser.add_argument("--saddr", type=str, required=True, help="Source IP address")
    parser.add_argument("--daddr", type=str, required=True, help="Destination IP address")
    args = parser.parse_args()
    
    # CRITICAL: Convert IPs to network-order integers for the C code.
    # The kernel stores and compares IP addresses in network byte order (big-endian).
    # socket.inet_aton produces this format. struct.unpack requires "!I" to
    # unpack it into an integer while preserving the network byte order.
    # Using "=" or "<" would cause the filter to fail on little-endian machines.
    saddr_n = struct.unpack("!I", socket.inet_aton(args.saddr))[0]
    daddr_n = struct.unpack("!I", socket.inet_aton(args.daddr))[0]
    
    # The eBPF C program
    bpf_text = """
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <linux/skbuff.h>
    #include <net/ip.h>
    
    #define SRC_IP_PLACEHOLDER 0x0
    #define DST_IP_PLACEHOLDER 0x0
    
    BPF_STACK_TRACE(stack_traces, 1024);
    
    int trace_kfree_skb(struct pt_regs *ctx, struct sk_buff *skb) {
        if (!skb) { return 0; }
        if (skb->mac_header >= skb->network_header) { return 0; }
    
        struct iphdr *ip = (struct iphdr *)(skb->head + skb->network_header);
    
        if (ip->saddr == SRC_IP_PLACEHOLDER && ip->daddr == DST_IP_PLACEHOLDER) {
            int stack_id = stack_traces.get_stackid(ctx, 0);
            if (stack_id >= 0) {
                bpf_trace_printk("Packet dropped, stack_id=%d\n", stack_id);
            }
        }
        return 0;
    }
    """
    
    bpf_text = bpf_text.replace("SRC_IP_PLACEHOLDER", f"0x{saddr_n:08x}")
    bpf_text = bpf_text.replace("DST_IP_PLACEHOLDER", f"0x{daddr_n:08x}")
    
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")
    
    print(f"Tracing drops for {args.saddr} -> {args.daddr}... Press Ctrl-C to stop.")
    
    try:
        while True:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            if b"Packet dropped" in msg:
                msg_str = msg.decode('utf-8')
                stack_id = int(msg_str.split("=")[1])
                
                print("\n" + "="*20 + " PACKET DROP DETECTED " + "="*20)
                print(f"Timestamp: {ts:.9f}")
                
                stack = b.get_table("stack_traces")
                for addr in stack.walk(stack_id):
                    sym = b.ksym(addr, show_offset=True)
                    print(f"\t{sym.decode('utf-8')}")
                print("="*62 + "\n")

    except KeyboardInterrupt:
        print("Detaching...")
        exit()
    
    ```
*   **Interpretation:** When you run this script and generate the target traffic, it will print a full kernel stack trace at the moment of a matching packet drop.
    ```
    ==================== PACKET DROP DETECTED ====================
    Time: 12345.6789
        kfree_skb+0x0 [kernel]
        ip_rcv_finish.constprop.0+0x392 [kernel]
        ip_rcv+0x2a0 [kernel]
        netif_receive_skb_core+0x1a2 [kernel]
        ... (driver functions) ...
    ==============================================================
    ```
    This trace is the definitive ground truth. It shows the packet was received by the driver, passed up to `ip_rcv`, and then dropped inside `ip_rcv_finish`. This allows you to open the kernel source for that exact function and see the specific logic (e.g., the `fib_validate_source` call for RPF) that triggered the drop.

## Summary and Recommended Workflow

For any "disappearing packet" problem on a Linux host, follow this systematic workflow:

1.  **`tcpdump`:** Confirm the packet is arriving on the host's interface. If not, the problem is external.
2.  **`nftrace`:** If the packet arrives, use `nftrace` to definitively rule out the firewall.
3.  **`dropwatch`:** If `nftrace` is silent, use `dropwatch` to quickly identify the kernel subsystem and function responsible for the drop.
4.  **eBPF:** If `dropwatch` isn't enough and you need a full stack trace or more context, use a targeted eBPF script to get the final, unambiguous answer.