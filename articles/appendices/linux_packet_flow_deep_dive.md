# Linux Packet Flow: A Deep Dive into `tcpdump` vs. Netfilter

## Introduction

When diagnosing network issues on Linux, two of the most powerful tools at our disposal are `tcpdump` and `nftables` (or its predecessor, `iptables`). While both operate on network packets, they do so at fundamentally different stages of the kernel's packet processing path. A common point of confusion is when `tcpdump` shows a packet arriving, but Netfilter rules seem to ignore it completely. This is not a bug; it's a feature of the kernel's layered architecture.

This document provides a deep dive into the journey of an incoming packet, explaining precisely where `tcpdump` gets its copy and where the Netfilter path begins. Understanding this distinction is the key to resolving a whole class of "disappearing packet" mysteries.

---

## The Journey of an Ingress Packet

Let's trace the path of a single packet from the moment the network interface card (NIC) receives it.

### Stage 1: The Hardware and the Driver

1.  **Physical Reception:** The NIC's hardware receives the electrical/optical signals and decodes them into an Ethernet frame. The frame is placed into a buffer in the NIC's memory.
2.  **DMA Transfer:** The NIC uses Direct Memory Access (DMA) to transfer the frame from its own memory into a pre-allocated ring buffer in the kernel's memory. This avoids involving the CPU in the memory copy, making it highly efficient.
3.  **Hardware Interrupt:** The NIC raises an interrupt to signal to the CPU that a new frame has arrived in the ring buffer.

### Stage 2: The Driver's Initial Processing

The CPU acknowledges the interrupt and executes the NIC driver's interrupt service routine.

1.  **`sk_buff` Allocation:** The driver allocates a kernel `struct sk_buff` (socket buffer), which is the standard data structure for representing a packet within the kernel.
2.  **Data Transfer:** The frame data is moved from the DMA ring buffer into the `sk_buff`.
3.  **`napi_gro_receive()`:** The driver then passes the `sk_buff` to the `napi_gro_receive()` function. This is the main hand-off point from the driver to the generic network stack.

### Stage 3: The `netif_receive_skb()` Junction - Where Paths Diverge

The `napi_gro_receive()` function eventually calls `netif_receive_skb()`, which represents a critical junction in the packet's journey. It is here that the path splits.

Inside `netif_receive_skb()`, the kernel iterates through a list of "packet type handlers" that have registered themselves to receive copies of all (or some) incoming packets.

**This is where `tcpdump` hooks in.** When `tcpdump` (or any other `libpcap`-based tool) starts, it creates a special `AF_PACKET` socket. This type of socket registers itself as one of these packet type handlers.

When `netif_receive_skb()` processes our incoming packet, it sees the `AF_PACKET` handler in the list and creates a *clone* of the `sk_buff` to be queued for that socket. `tcpdump`, running in userspace, reads from this socket and displays the packet on your screen.

Crucially, this is a **copy** of the packet. The original `sk_buff` continues its journey down the network stack.

### Stage 4: The Netfilter `PREROUTING` Hook

After the `AF_PACKET` handlers have been serviced, `netif_receive_skb()` passes the original `sk_buff` to the IP protocol handler, `ip_rcv()`. After performing basic sanity checks (header length, checksum, etc.) in a helper function, `ip_rcv()` immediately submits the packet to the Netfilter framework.

This is the first point at which an `nftables` rule can see and act upon the packet. The packet traverses the chains attached to the `NF_INET_PRE_ROUTING` hook, typically including `raw`, `mangle`, and `nat` tables.

### Stage 5: The Routing Decision and Unicast RPF Check

**Only if the packet is accepted by the `prerouting` hook** does execution continue. The kernel then calls the continuation function, `ip_rcv_finish()`, which is responsible for the routing decision.

Inside this function, the kernel consults the Forwarding Information Base (FIB) to determine if the packet is destined for the local host or needs to be forwarded. It is during this FIB lookup that the **unicast Reverse Path Filtering (RPF) check** is performed.

If `rp_filter` is enabled on the ingress interface, the kernel checks if a valid route back to the packet's source IP exists via that same interface. If the check fails, the packet is dropped here.

---

## Conclusion: The "Disappearing Packet" Explained

The mystery of the disappearing packet is now clear. The processing path can be visualized as follows:

```
[ NIC / Driver ] -> [ netif_receive_skb() ] -> [ ip_rcv_core() ] -> [ Netfilter PREROUTING ] -> [ ip_rcv_finish() ]
                         |                      |                      |                        |
                         |                      |                      |                        +--> (Packet dropped by Unicast RPF)
                         |                      |                      |
                         |                      |                      +--> (Packet dropped by nftables rule)
                         |                      |
                         |                      +--> (Packet dropped by header sanity check)
                         |
                         +--> (Copy to AF_PACKET socket for tcpdump)
```

If `tcpdump` shows the packet but your `nftrace` is empty, the cause is almost certainly one of the initial sanity checks in `ip_rcv_core()` (e.g., `PACKET_OTHERHOST` classification). If `nftrace` *does* show the packet but it still disappears, the drop is likely happening either in a later Netfilter hook (like `INPUT`) or during the RPF check in `ip_rcv_finish()`.

## A Practical Guide to Tracing Packets with `nftables`

The theory above is essential, but a practical, working example is the best way to confirm your understanding and build a reliable diagnostic harness. The following is a step-by-step guide to the most reliable method for tracing a packet's journey through the Netfilter hooks.

### Key Lessons Learned

Through experimentation, several common pitfalls were identified:

1.  **Do NOT rely on `dmesg`:** On many systems, `nftables log` actions do **not** send their output to the kernel ring buffer (`dmesg`). The output is sent to a netlink socket that requires a specific userspace listener.
2.  **The Correct Tool is `nft monitor trace`:** The `nft monitor` command is the correct listener. Specifically, `nft monitor trace` is used to view the detailed trace output generated by `nftables` rules.
3.  **Tracing Requires `meta nftrace set 1`:** For a packet to be traced, the `nftables` rule it matches must include the `meta nftrace set 1` statement. This flags the packet for detailed tracing.
4.  **Local Packets Traverse `lo`:** As we will see in the example, packets generated locally (e.g., with `ping`) that are also destined for a local IP address will traverse the loopback interface (`lo`), regardless of what other interfaces are configured. Your `nftables` rules must match on `iif "lo"` and `oif "lo"` to see this traffic.

### The "Positive Confirmation" Example

This example provides a complete, working script to demonstrate a successful `nftables` trace in the simplest possible environment. It serves as a "ground truth" test to confirm your tools are working as expected.

**1. The Goal:** Create a single namespace, send a single `ping` to a local IP, and observe the packet hitting all four key Netfilter hooks (`output`, `postrouting`,- `prerouting`, and `input`).

**2. The Setup Script:**

This can be run directly in a shell. It creates a namespace `ns-simple` with a `dummy0` interface holding the IP `192.168.100.1`.

```sh
# --- Environment Setup ---
sudo ip netns del ns-simple
sudo ip netns add ns-simple
sudo ip netns exec ns-simple ip link add dummy0 type dummy
sudo ip netns exec ns-simple ip addr add 192.168.100.1/24 dev dummy0
sudo ip netns exec ns-simple ip link set dummy0 up
sudo ip netns exec ns-simple ip link set lo up

# --- Disable RPF (Good practice for testing) ---
sudo ip netns exec ns-simple sysctl -w net.ipv4.conf.all.rp_filter=0
sudo ip netns exec ns-simple sysctl -w net.ipv4.conf.default.rp_filter=0
sudo ip netns exec ns-simple sysctl -w net.ipv4.conf.dummy0.rp_filter=0
```

**3. The `nftables` Ruleset:**

Save this to a file (e.g., `trace-rules.nft`) and load it into the namespace with `sudo ip netns exec ns-simple nft -f trace-rules.nft`.

```nft
# trace-rules.nft
flush ruleset

table ip filter {
  chain output {
    type filter hook output priority raw; policy accept;
    oif "lo" ip saddr 192.168.100.1 meta nftrace set 1
    log prefix "nft_test_output " accept
  }

  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
    iif "lo" ip saddr 192.168.100.1 meta nftrace set 1
    log prefix "nft_test_prerouting " accept
  }

  chain postrouting {
    type filter hook postrouting priority raw; policy accept;
    oif "lo" ip saddr 192.168.100.1 meta nftrace set 1
    log prefix "nft_test_postrouting " accept
  }

  chain input {
    # Note: The hook is 'input', not 'prerouting' as in a previous typo.
    type filter hook input priority raw; policy accept;
    iif "lo" ip saddr 192.168.100.1 meta nftrace set 1
    log prefix "nft_test_input " accept
  }
}
```

**4. Running the Test:**

You will need two terminals, both inside the namespace (`sudo ip netns exec ns-simple bash`).

*   **In Terminal 1 (The Monitor):** Start the tracer. It will appear to hang, waiting for events.
    ```sh
    nft monitor trace
    ```

*   **In Terminal 2 (The Action):** Send a single `ping`.
    ```sh
    ping -c 1 192.168.100.1
    ```

**5. Expected Output:**

As soon as the `ping` is sent, Terminal 1 will display a detailed trace. The key lines to look for are the log prefixes, which confirm the packet hit each hook:

```
...
trace id ... ip filter output rule log prefix "nft_test_output " accept (verdict accept)
...
trace id ... ip filter postrouting rule log prefix "nft_test_postrouting " accept (verdict accept)
...
trace id ... ip filter prerouting rule log prefix "nft_test_prerouting " accept (verdict accept)
...
trace id ... ip filter input rule log prefix "nft_test_input " accept (verdict accept)
...
```

This successful test provides a solid, reliable baseline. Any further packet tracing experiments can be built upon this proven methodology.
