# Netfilter NAT and Multicast: A Source Code Analysis

This document summarizes the findings of a deep dive into the Linux kernel source code (based on a 6.x series kernel) to determine how and why Network Address Translation (NAT) interacts with multicast traffic.

## Executive Summary (TL;DR)

*   **Multicast SNAT is impossible.** This is not due to a simple rule but is a fundamental consequence of the kernel's network architecture. SNAT is architecturally a `POST_ROUTING` operation, but multicast traffic is diverted to a separate processing path long before that hook is reached. Functionally, SNAT would break the Reverse Path Forwarding (RPF) check, which is essential for loop-free multicast routing.

*   **Multicast DNAT is theoretically possible but highly problematic.** DNAT occurs in the `PREROUTING` hook, before the multicast/unicast packet paths diverge. The connection tracking code does not explicitly forbid tracking a multicast packet. However, using it would have complex side effects, such as converting a multicast stream to unicast or interfering with multicast routing protocols. It is not a standard or recommended configuration.

The core reason for this behavior is the **intentional segregation of multicast traffic** into a specialized, high-performance forwarding path that bypasses the connection tracking system upon which Netfilter's NAT implementation depends.

---

## Detailed Analysis

### 1. The Packet Path Divergence

The key to understanding the behavior lies in the incoming packet path defined in `linux/net/ipv4/ip_input.c`.

1.  **`ip_rcv()`**: All IPv4 packets enter here.
2.  **`NF_INET_PRE_ROUTING` Hook**: The packet first traverses the `PREROUTING` hook. This is where DNAT operations are evaluated and where connection tracking is initiated for unicast traffic via `nf_conntrack_in`.
3.  **`ip_rcv_finish_core()`**: After the hook, this function performs a route lookup.
4.  **Routing Decision**: The route lookup determines the packet's destination. For a multicast packet, the destination's `input` function pointer is set to `ip_mr_input`.
5.  **`dst_input()`**: This function executes the `input` pointer.
    *   **Unicast packets** are sent to `ip_local_deliver` or `ip_forward`, continuing through the standard Netfilter chains (`FORWARD`, `POST_ROUTING`, etc.).
    *   **Multicast packets** are sent directly to `ip_mr_input` in `linux/net/ipv4/ipmr.c`.

This diversion is the critical point. Once a packet enters `ip_mr_input`, it is on a specialized multicast-only forwarding path.

### 2. Why SNAT Fails

SNAT (Source NAT), and particularly `MASQUERADE`, is fundamentally a `POST_ROUTING` operation.

#### Architectural Reason

The kernel needs to know the **outgoing interface** to select the correct source IP address for SNAT. This information is only available after the routing decision has been made. The code enforces this; for example, `nf_nat_masquerade_ipv4()` contains the check `WARN_ON(hooknum != NF_INET_POST_ROUTING)`. Since multicast traffic is diverted to `ip_mr_input` *before* the `POST_ROUTING` hook, it never reaches the point where SNAT could be applied.

#### Functional Reason

Even if one could force SNAT to occur earlier, it would break multicast routing. The multicast forwarding engine (`ipmr.c`) relies on the **source IP address** to perform a Reverse Path Forwarding (RPF) check. This check ensures that the packet is arriving on the correct interface that leads back to the source, which is the primary mechanism for preventing routing loops and building the multicast distribution tree.

Changing the source address would cause the RPF check to fail, and the packet would be dropped. The source address is a fundamental part of a multicast stream's identity (`S,G` entry), and altering it invalidates the stream from the perspective of all downstream routers.

### 3. Why DNAT is Theoretically Possible

DNAT (Destination NAT) is a `PREROUTING` operation.

#### Architectural Possibility

Because the `PREROUTING` hook runs *before* the route lookup and path divergence, a multicast packet is processed by the same hook as a unicast packet. Our analysis of `nf_conntrack_core.c` showed that the core connection tracking functions (like `nf_ct_get_tuple`) do **not** have explicit checks to forbid the creation of a conntrack entry for a packet with a multicast destination.

Therefore, Netfilter could create a conntrack entry for an incoming multicast packet, apply a DNAT rule, and modify the packet's destination address.

#### Functional Problems

While architecturally possible, the functional implications are severe:

*   **Multicast-to-Unicast:** If the destination is changed to a unicast IP, the packet is effectively converted into a unicast packet. The conntrack entry would handle the reply traffic correctly. This is a niche but potentially valid use case for a multicast-to-unicast gateway.
*   **Multicast-to-Multicast:** If the destination is changed to another multicast group, it could confuse multicast routing daemons (like `pimd`) and would require careful management of IGMP memberships on the host to ensure the translated packet is actually processed.

Because of these complexities, DNAT on multicast traffic is not a standard feature and should be considered experimental with unpredictable results in a complex multicast environment.
