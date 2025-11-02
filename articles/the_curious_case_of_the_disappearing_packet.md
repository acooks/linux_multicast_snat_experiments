# Debugging Linux Multicast - A romcom for networking nerds

## The Curious Case of the Disappearing Packet

Every network engineer eventually encounters the phantom packet. Sometimes that's an IPSec issue, but today it's multicast. Specifically a multicast stream that `tcpdump` confirms is on the wire, yet never reaches its destination application. This is particularly frustrating when dealing with unconfigurable devices, like a video camera with a hard-coded, unroutable source IP, where the intuitive solution—a simple `nftables` SNAT rule—fails without clear explanation.

This article chronicles a deep dive into such a problem. It's a journey through the Linux kernel's multicast forwarding mechanisms, Netfilter's intricate hooks, and the often-surprising architectural decisions that govern packet flow. We'll share the systematic approach, the diagnostic tools, and the experimental methodology that allowed us to uncover why standard solutions fail and what truly works. By the end, you and I will have an practical understanding of Linux multicast, and new tools to debug and implement solutions for everyday multicast challenges. :)

---

## Lifting the Lid on the Black Box

Before you can solve a mystery, you need the right tools to see the crime scene. Our first challenge was that the most common and familiar tools for network observability were insufficient for this task, leaving us debugging in the dark.

### Why `tcpdump` Isn't Enough

The first instinct for any network engineer is to use `tcpdump`. We can run it on the ingress interface (e.g., `eth0`) and the egress interface (e.g., `eth1`) and compare the results.

```bash
# Terminal 1
sudo tcpdump -i eth0 host 224.1.1.1

# Terminal 2
sudo tcpdump -i eth1 host 224.1.1.1
```

`tcpdump` will show you the packet arriving at `eth0` and its conspicuous absence at `eth1`. This tells you _that_ the packet disappeared, but it gives you zero information about _where_ or _why_ it disappeared. The entire Linux kernel network stack—including Netfilter hooks, RPF checks, and forwarding decisions—sits between those two interfaces. For `tcpdump`, this is a complete black box. To find our packet, we needed a tool that could trace its journey _inside_ that box.

### Choosing the Right Internal Tracing Tool

When it comes to tracing activity inside the Linux kernel, there are several powerful options:

- **eBPF (`bpftrace`, `bcc`):** This is the modern, incredibly powerful answer to kernel tracing. It allows you to write small, safe programs that can be attached to almost any kernel function to observe behavior. For a complex or unknown problem, eBPF is often the best tool. However, it comes with a steeper learning curve and requires a separate toolchain.
- **`strace`:** This tool is excellent for tracing system calls, making it invaluable for debugging the _control plane_ (e.g., watching the calls our `pymfcd` daemon makes). However, it is the wrong tool for tracing the _data plane_, as a packet's journey through the kernel does not involve system calls.
- **`nftables` Tracing:** Since our original problem was an attempt to use `nftables` for NAT, the most logical and direct starting point was to use the debugging tools built into `nftables` itself. It allows us to test our hypothesis within the specific subsystem we are trying to use. Reaching for a more complex tool like eBPF would be premature if the native tool could provide the answer.

We started with `nftables` not just as a solution, but as our primary diagnostic tool.

### The Ground Truth Tool: `nft monitor trace`

To get true, unambiguous visibility into Netfilter's inner workings, you need to combine two things: an `nftables` rule that explicitly flags packets for tracing, and the `nft monitor trace` command itself. This combination is your new best friend for kernel-level debugging of dropped packets.

**Step 1: Create an Isolated Lab with Network Namespaces**

Seriously, never experiment on a live system. Network namespaces are a lightweight, built-in feature of the Linux kernel that allow you to create fully isolated network stacks. They're perfect for building a controlled lab environment.

```bash
# Create a new, isolated network namespace
sudo ip netns add ns-lab

# Create a dummy interface inside it to generate and receive traffic
sudo ip -n ns-lab link add dummy0 type dummy
sudo ip -n ns-lab addr add 192.168.100.1/24 dev dummy0
sudo ip -n ns-lab link set dummy0 up
sudo ip -n ns-lab link set lo up # Always bring up loopback
```

**Step 2: Write a Tracing Ruleset**

Create a file (e.g., `trace-rules.nft`) with rules that explicitly enable tracing. The magic incantation here is `meta nftrace set 1`. This flag tells the kernel to generate detailed trace events for any packet that matches the rule, giving you a granular view of its path.

```nft
# File: trace-rules.nft
table ip filter {
  chain input {
    type filter hook input priority raw; policy accept;
    # For any packet coming in on the loopback, turn on tracing
    iif "lo" meta nftrace set 1
    # Then, log it with a unique prefix for easy identification
    log prefix "NFT_INPUT_TRACE: " accept
  }
  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
    iif "lo" meta nftrace set 1
    log prefix "NFT_PREROUTING_TRACE: " accept
  }
}
```

**Step 3: Run the Monitor and Generate Traffic**

Open two separate terminal windows.

In **Terminal 1**, start the `nft monitor trace` command. It will immediately begin listening for trace events within your `ns-lab` namespace.

```bash
# Terminal 1: Start the monitor
sudo ip netns exec ns-lab nft monitor trace
```

In **Terminal 2**, load your tracing ruleset and then generate a single packet. A simple `ping` to the dummy interface is perfect for this "ground truth" test.

```bash
# Terminal 2: Load rules and send a ping
sudo ip netns exec ns-lab nft -f trace-rules.nft
sudo ip netns exec ns-lab ping -c 1 192.168.100.1
```

**Step 4: Analyze the Output**

Back in Terminal 1, you'll be greeted with a beautifully verbose, unambiguous trace of the packet's journey through the Netfilter hooks.

```
...
trace id 1a2b3c4d ip filter prerouting rule log prefix "NFT_PREROUTING_TRACE: " accept
...
trace id 1a2b3c4d ip filter input rule log prefix "NFT_INPUT_TRACE: " accept
...
```

This experiment, replicated in [`test_nft_trace.py`](https://github.com/acooks/linux_netfilter_mcast_experiments/blob/main/mcast_lab/tests/test_nft_trace.py) in this project, provides our first, rock-solid proven fact: **`nft monitor trace` is the authoritative tool for observing Netfilter behavior.** If you're not seeing what you expect, this is where you start.

---

## No Entry Without a Return Ticket

Now that we can reliably see inside the kernel, we can tackle the prime suspect for our disappearing multicast packet: the **Reverse Path Forwarding (RPF) check**. We needed to confirm that the RPF check happens _after_ the `prerouting` hook. If that weren't true, Netfilter would never even get a chance to see our packet, let alone SNAT it. It's time to design an experiment to prove or disprove this.

**Step 1: Build the RPF Test Environment**

To properly test the RPF check, we need two network namespaces to simulate a source and a router. The "router" namespace (`ns-router`) will have the RPF check explicitly enabled, and our "source" namespace (`ns-source`) will send traffic from an IP address that the router considers "unroutable" via the ingress interface.

```bash
# Create the namespaces
sudo ip netns add ns-source
sudo ip netns add ns-router

# Create the virtual link (veth pair) between them
sudo ip link add veth-s type veth peer name veth-r
sudo ip link set veth-s netns ns-source
sudo ip link set veth-r netns ns-router

# Configure the source namespace
sudo ip -n ns-source addr add 192.168.1.1/24 dev veth-s
sudo ip -n ns-source link set veth-s up
# Add the "unroutable" IP. Crucially, the router will have no route back to this via veth-r.
sudo ip -n ns-source addr add 10.0.0.100/32 dev veth-s
sudo ip -n ns-source link set lo up

# Configure the router namespace
sudo ip -n ns-router addr add 192.168.1.2/24 dev veth-r
sudo ip -n ns-router link set veth-r up
sudo ip -n ns-router link set lo up

# CRITICAL: Explicitly enable RPF in the router namespace.
# We set it for all interfaces and specifically for veth-r for clarity.
sudo ip netns exec ns-router sysctl -w net.ipv4.conf.all.rp_filter=1
sudo ip netns exec ns-router sysctl -w net.ipv4.conf.veth-r.rp_filter=1
```

**Step 2: Create a Multi-Stage Tracing Ruleset**

In our `ns-router`, we'll install a simple `nftables` ruleset (`rpf-trace.nft`) designed to trace packets at both the `prerouting` and `input` hooks. This will tell us exactly where the packet is dropped.

```nft
# File: rpf-trace.nft
table ip filter {
  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
    iif "veth-r" meta nftrace set 1
    log prefix "RPF_TEST_PREROUTING: " accept
  }
  chain input {
    type filter hook input priority raw; policy accept;
    iif "veth-r" meta nftrace set 1
    log prefix "RPF_TEST_INPUT: " accept
  }
}
```

**Step 3: Run the Experiment**

As before, open two terminals.

In **Terminal 1**, start `nft monitor trace` in the `ns-router` namespace.

```bash
# Terminal 1
sudo ip netns exec ns-router nft monitor trace
```

In **Terminal 2**, load the `rpf-trace.nft` ruleset into `ns-router`, and then send a multicast packet from `ns-source` using the **unroutable** source IP (`10.0.0.100`).

```bash
# Terminal 2
sudo ip netns exec ns-router nft -f rpf-trace.nft
sudo ip netns exec ns-source nc -u -s 10.0.0.100 -w 1 224.1.1.1 12345 <<< "test_multicast_data"
```

**Step 4: Analyze the Result - The Smoking Gun**

The output in Terminal 1 (from `nft monitor trace`) is the definitive proof. You will observe something like this:

```
...
trace id 5e6f7g8h ip filter prerouting rule log prefix "RPF_TEST_PREROUTING: " accept
...
# --- ABSOLUTE SILENCE HERE ---
```

Crucially, the log for `RPF_TEST_INPUT` will be entirely missing. This is the empirical evidence we needed. The packet was undeniably seen by the `prerouting` hook, but it was dropped _before_ it could reach the `input` hook.

This experiment (replicated in [`test_rpf_failure.py`](https://github.com/acooks/linux_netfilter_mcast_experiments/blob/main/mcast_lab/tests/test_rpf_failure.py) in this project) confirms our understanding of the ordering. Showing that the RPF check occurs _after_ the `prerouting` hook but _before_ the `input` hook was essential, as it meant our plan to use an SNAT rule in `prerouting` was at least plausible. The next step was to test it directly.

---

## No Translations for Fairies

With the RPF check's position confirmed, our confidence was high. The next logical step was to implement the `nftables` SNAT rule in `prerouting` to change the unroutable source IP to a routable one, allowing the packet to pass RPF and be forwarded. Armed with this knowledge, we run the final experiment, [`test_multicast_snat_rpf.py`](https://github.com/acooks/linux_netfilter_mcast_experiments/blob/main/mcast_lab/tests/test_multicast_snat_rpf.py). The setup is the same, but the `nftables` rule is different.

```nft
# Attempted SNAT rule (Spoiler: This fails!)
table ip nat {
  chain prerouting {
    type nat hook prerouting priority -150; policy accept;
    iif "veth-r" ip saddr 10.0.0.100 ip daddr 224.1.1.1 snat to 192.168.1.2
  }
}
```

But when we tried to load this rule, the `nft` command itself failed instantly, returning a cryptic but absolute error: **"Error: Operation not supported."** The kernel was rejecting our rule outright.

This wasn't a packet drop; it was an architectural "no." The reason lies in a fundamental design choice within the Linux kernel's Netfilter framework. All NAT operations, by their very nature, depend on the **connection tracking subsystem (`conntrack`)**. `conntrack` is responsible for maintaining state about network connections, which is essential for translating addresses consistently.

However, multicast is, by definition, a one-to-many, connectionless protocol. The concept of a "connection" simply doesn't apply. The kernel's `conntrack` code contains an explicit check that **refuses to create a tracking entry for any incoming multicast packet.**

The implications are clear:

- To perform NAT, you need `conntrack`.
- `conntrack` explicitly refuses to track incoming multicast.
- Therefore, you cannot perform NAT on incoming multicast packets.

This is the architectural dead end. The Linux kernel's Netfilter architecture makes the goal of SNAT'ing an incoming multicast packet in the `prerouting` hook impossible. The kernel isn't being difficult; it's enforcing sound internal logic.

---

## Direct MFC Control: The Other Half of the Puzzle

Our original plan to handle unroutable multicast involved two main components: `nftables` SNAT (which we proved impossible) and direct control over the kernel's Multicast Forwarding Cache (MFC). While the SNAT part failed, the investigation into MFC control itself yielded crucial, unexpected insights.

This section details _how_ to directly command the kernel's multicast forwarding table. It's important to reiterate that while this is essential for any static multicast routing, it does **not** magically fix the RPF problem for unroutable sources. The kernel will still perform an RPF check on traffic before consulting the MFC rules we inject. However, for **routable multicast sources**, direct MFC control provides a powerful and precise way to statically route traffic without the overhead of dynamic routing protocols like PIM.

This is where we discover the "Two-API Reality": you must use the old, legacy `setsockopt` API to _write_ these static multicast routes.

### The Ground Truth: C and `setsockopt`

The file [`mfc_c_test.c`](https://github.com/acooks/linux_netfilter_mcast_experiments/blob/main/mcast_lab/src/mfc_c_test.c) provides a working reference implementation in C. It shows the precise sequence of system calls needed to program the kernel's MFC directly. This code is the empirical proof that this method works.

```c
// Abridged example from mfc_c_test.c - Demonstrates direct MFC programming

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/mroute.h> // Contains MRT_INIT, MRT_ADD_VIF, etc.

void die(const char *s) {
    perror(s);
    exit(1);
}

int main(int argc, char *argv[]) {
    // ... (argument parsing and setup) ...

    // 1. Get a special raw socket for IGMP protocol
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
    if (sock < 0) die("socket");

    // 2. Tell the kernel you want to control multicast routing (MRT_INIT)
    if (setsockopt(sock, IPPROTO_IP, MRT_INIT, &(int){1}, sizeof(int)) < 0) die("setsockopt MRT_INIT");

    // 3. Create a Virtual Interface (VIF) for the input interface (VIF 0)
    struct vifctl vc_in;
    memset(&vc_in, 0, sizeof(vc_in));
    vc_in.vifc_vifi = 0; // Assign VIF index 0
    vc_in.vifc_flags = VIFF_USE_IFINDEX; // Use interface index
    vc_in.vifc_lcl_ifindex = atoi(argv[1]); // Input interface index
    if (setsockopt(sock, IPPROTO_IP, MRT_ADD_VIF, &vc_in, sizeof(vc_in)) < 0) die("setsockopt MRT_ADD_VIF 0");

    // 4. Create a VIF for the output interface (VIF 1)
    struct vifctl vc_out;
    memset(&vc_out, 0, sizeof(vc_out));
    vc_out.vifc_vifi = 1; // Assign VIF index 1
    vc_out.vifc_flags = VIFF_USE_IFINDEX; // Use interface index
    vc_out.vifc_lcl_ifindex = atoi(argv[2]); // Output interface index
    if (setsockopt(sock, IPPROTO_IP, MRT_ADD_VIF, &vc_out, sizeof(vc_out)) < 0) die("setsockopt MRT_ADD_VIF 1");

    // 5. Create the Multicast Forwarding Cache (MFC) entry
    struct mfcctl mfc;
    memset(&mfc, 0, sizeof(mfc));
    mfc.mfcc_origin.s_addr = inet_addr("192.168.1.1"); // The routable source IP
    mfc.mfcc_mcastgrp.s_addr = inet_addr("224.1.1.1"); // The multicast group IP
    mfc.mfcc_parent = 0;                               // Input is VIF 0
    mfc.mfcc_ttls[1] = 1;                              // Set TTL > 0 for output VIF 1
    if (setsockopt(sock, IPPROTO_IP, MRT_ADD_MFC, &mfc, sizeof(mfc)) < 0) die("setsockopt MRT_ADD_MFC");

    printf("[C Tool] SUCCESS: VIFs and MFC entry added. Holding for 10s...\n");
    sleep(10); // Keep the socket open to maintain the route

    // ... (cleanup) ...
    return 0;
}
```

### The User-Friendly Solution: `pymfcd`

While C provides the "ground truth," writing and maintaining C daemons for every experiment is cumbersome. To make this correct approach more accessible, we created `pymfcd`, a Python-native daemon and command-line tool, as a direct result of this investigation. The project is now available on GitHub: [https://github.com/acooks/pymfcd](https://github.com/acooks/pymfcd).

It abstracts away the complexities of the `setsockopt` API and the manual management of Virtual Interfaces (VIFs). The daemon automatically handles VIF creation and reference counting when you add or remove MFC rules, allowing you to work directly with familiar interface names.

The [`run_experiment_instructive.py`](https://github.com/acooks/linux_netfilter_mcast_experiments/blob/main/mcast_lab/src/run_experiment_instructive.py) script in this project demonstrates how to orchestrate this, but the core operation is a single, simple command. To solve the problem of statically routing our _routable_ multicast source, you would:

```bash
# 1. Ensure the pymfcd daemon is running in the background within our router namespace.
#    (The PYTHONPATH is crucial here, pointing to the vendored library location.)
sudo ip netns exec ns-router env PYTHONPATH=./mcast_lab/src/pymfcd_vendored \
    python3 -m pymfcd.daemon_main &

# 2. Add the forwarding rule with a single, declarative command.
#    The daemon handles creating VIFs for veth-r and eth1 automatically.
sudo ip netns exec ns-router env PYTHONPATH=./mcast_lab/src/pymfcd_vendored \
    python3 -m pymfcd.mfc_cli mfc add \
    --iif veth-r \
    --oifs eth1 \
    --group 224.1.1.1 \
    --source 192.168.1.1
```

This single command achieves the goal. The kernel is now explicitly instructed to forward the packets, demonstrating a much cleaner and more robust way to manage static multicast routes compared to writing a custom C daemon.

---

## Limitations and Architectural Alternatives

The direct MFC programming approach detailed here is a powerful and precise solution for its intended use case: statically forwarding multicast from a known, routable source to a limited number of subnets or VLANs. However, it's crucial to understand its boundaries and to know when a different architectural approach is required.

### The Kernel's Hard Scaling Limit: `MAXVIFS=32`

The native Linux multicast forwarding engine, which our `pymfcd` solution controls, has a hard-coded, compile-time limit of **32 Virtual Interfaces (VIFs)**. Each `MRT_ADD_VIF` call consumes one of these VIFs. This makes the solution perfectly adequate for a router connecting a few dozen interfaces, but it is an architectural dead-end for scenarios requiring high interface density, such as in a data center switch or a large broadcast facility.

### Architectural Alternative 1: Modern Data Planes (OVS & EVPN)

When you hit the `MAXVIFS` scaling wall, the industry-standard solution is to move away from the native kernel forwarding plane to a more advanced data plane.

- **Open vSwitch (OVS):** OVS implements its own highly-optimized forwarding path in the kernel. For multicast, it uses "Group Tables" to efficiently manage multicast replication, completely bypassing the kernel's native MFC and its limitations.
- **EVPN (Ethernet VPN):** In modern data center fabrics, EVPN provides a control plane for managing network tunnels. Its approach to multicast, known as Ingress Replication, is to convert a multicast stream into a series of unicast packets at the first-hop switch (the "ingress"). These unicast packets are then sent through the network to each destination, where they can be converted back to multicast if needed.

### Architectural Alternative 2: The Userspace Multicast Relay

A different approach to the original "unroutable source" problem is to handle it at the application layer. A **userspace multicast relay** is a program that:

1.  **Receives:** It joins the problematic multicast group (e.g., 224.1.1.1 from source 10.0.0.100) just like any other multicast client.
2.  **Retransmits:** It takes the data from that stream and immediately retransmits it as a _new_ multicast stream, but this time sourced from a clean, routable IP address on the router itself (e.g., a loopback address).

This "launders" the stream. The newly transmitted multicast is now fully compliant with RPF checks and can be easily integrated into a standard multicast routing environment that uses protocols like PIM, without requiring any direct manipulation of the kernel's MFC.

## Conclusion: A Journey of Discovery and Redefinition

Our journey began with a clear, ambitious goal: to create a simple, static multicast router that could SNAT traffic from an unroutable source and then forward it using static MFC entries. We aimed to overcome the RPF problem and distribute multicast from a "bad" source address to any number of VLANs/subnets.

This investigation definitively proved that the SNAT component of our plan is **architecturally impossible** within the Linux kernel's Netfilter framework, due to `conntrack`'s explicit refusal to track multicast traffic. This single, critical finding invalidated our entire combined strategy for handling unroutable multicast sources in this manner.

However, the journey was far from a failure. In the process, we made several crucial discoveries about the other half of our original plan—static MFC control:

- We learned that `iproute2` (the `ip mroute` command) is insufficient for _writing_ static MFC entries, leading to the discovery of the "Two-API Reality" and the necessity of the legacy `setsockopt` API.
- We uncovered the requirement that the socket used for `setsockopt` must remain open for the MFC entries to persist, explaining why a daemon is necessary.
- This led to the creation of `pymfcd`, a robust, Python-native MFC controller. While `pymfcd` does not solve the unroutable source problem (as it cannot bypass the RPF check on its own), it is an incredibly useful tool for its intended purpose: **statically routing multicast from _routable_ sources** without the complexity of dynamic routing protocols like PIM.

Ultimately, our initial goal for unroutable multicast proved unattainable with the chosen tools. Yet, the investigation was a profound success. We gained a precise understanding of the kernel's behavior, definitively diagnosed an architectural limitation, and developed a valuable tool for a different, common class of multicast routing problems. This journey redefined our understanding of what's possible and how to approach complex kernel-level networking challenges.
