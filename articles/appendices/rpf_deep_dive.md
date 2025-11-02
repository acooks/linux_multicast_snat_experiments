# A Deep Dive into Linux Reverse Path Filtering (RPF)

This document serves as a plan and a repository for a deep, evidence-based investigation into the Linux kernel's Reverse Path Filtering (RPF) mechanism. The goal is to move beyond a high-level definition and produce an authoritative explanation of its behavior, implementation, and operational impact.

---

## 1. Objective

To produce a definitive document that fully explains the theory, implementation, and operational impact of the Linux kernel's Reverse Path Filtering mechanism for both unicast and multicast traffic. This includes its different modes (`strict` vs. `loose`), its interaction with modern routing features like multipath and policy routing, and its relevance in modern network security.

## 2. Methodology

The investigation will follow a multi-pronged research approach to ensure accuracy and depth:

1.  **Canonical Sources:** We will begin by analyzing the official Linux kernel documentation (`ip-sysctl.txt`) and relevant RFCs (e.g., RFC 3704 for unicast RPF, RFC 2827) to establish a baseline understanding of the intended behavior.

2.  **Source Code Analysis:** We will directly inspect the relevant functions in the Linux kernel source code to determine the precise, unambiguous logic. Key areas of interest include:
    *   `net/ipv4/fib_frontend.c`: For the generic unicast RPF check.
    *   `net/ipv4/ipmr.c`: For the specific multicast RPF check, to understand how it differs from or reuses the unicast logic.

3.  **Practical Experimentation:** We will design and execute a series of experiments using network namespaces, `veth` pairs, and the `iproute2` utilities. These experiments will be designed to create specific network topologies (symmetric, asymmetric, multi-homed) to practically demonstrate the effects of each `rp_filter` mode on packet forwarding and provide verifiable proof of the kernel's behavior.

## 3. Key Questions to Be Answered

This investigation will seek to provide definitive, evidence-based answers to the following questions:

1.  **The "Why":** What specific attack vector (e.g., IP spoofing in DoS reflection/amplification attacks) was RPF originally designed to mitigate?

2.  **Strict Mode (`rp_filter = 1`):** What is the exact sequence of checks the kernel performs? Is the check *only* "does the best route to the source exit via the ingress interface," or are other factors (like source reachability) considered?

3.  **Loose Mode (`rp_filter = 2`):** What is the exact logic? Does the kernel check if *a* route exists on *any* interface, and does that route have to be the *best* route? What happens if the source is reachable via multiple interfaces?

4.  **Interaction with Unicast:** How does RPF behave for a simple unicast packet from a spoofed source arriving on an unexpected interface? We will design an experiment to demonstrate this.

5.  **Interaction with Multicast:** How does the multicast RPF check (in `ipmr.c`) differ from the unicast check? Is it a completely separate mechanism, or does it reuse the same core `fib_lookup` logic?

6.  **Interaction with Multipath Routing:** What is the behavior when a valid source is reachable via multiple equal-cost routes (ECMP) over different interfaces? How does `strict` mode handle this scenario?

7.  **Interaction with Policy Routing:** What happens if the route back to the source exists, but in a different routing table (i.e., `ip rule` is in use)? Does the RPF check consult only the `main` table, or does it respect the policy routing rules?

8.  **Modern Relevance:** Is RPF still considered a best practice for network security on a host, or have modern stateful firewalling techniques (e.g., `nftables` connection tracking) largely superseded its original purpose?

---

## 4. Investigation Log

### 4.1. Canonical Sources Findings

**Summary of `rp_filter` from `ip-sysctl.rst`:**

The `rp_filter` sysctl controls **Reverse Path Filtering**, a mechanism to prevent IP spoofing. It can be configured per interface (`conf/interface/rp_filter`) or globally (`conf/all/rp_filter`), with the maximum value taking precedence.

It has three possible integer values:

*   **`0` - No source validation:** RPF is disabled. Packets are forwarded regardless of their source address validity.
*   **`1` - Strict mode (RFC3704 Strict Reverse Path):**
    *   Each incoming packet's source IP is tested against the kernel's Forwarding Information Base (FIB).
    *   If the interface on which the packet arrived is **not the best reverse path** (i.e., the interface that would be used to send a unicast packet *back to* the source IP), the packet check will fail.
    *   By default, failed packets are discarded.
    *   **Recommended practice:** RFC3704 recommends enabling strict mode to prevent IP spoofing in DDoS attacks.
*   **`2` - Loose mode (RFC3704 Loose Reverse Path):**
    *   Each incoming packet's source IP is tested against the FIB.
    *   If the source IP address is **not reachable via *any* interface** on the system (i.e., there is no route back to the source IP), the packet check will fail.
    *   **Recommended practice:** Loose mode is recommended if using asymmetric routing or other complicated routing setups where strict mode might incorrectly drop legitimate traffic.

**Default Value:** The default value is `0`, but the documentation notes that "some distributions enable it in startup scripts."

**Summary of RFC 3704:**

RFC 3704, "Ingress Filtering for Multihomed Networks," is a Best Current Practice document focused on mitigating Distributed Denial-of-Service (DoS) attacks by preventing IP spoofing. The core idea is to ensure that incoming traffic has a source address that is legitimately routable back to the network from which it originated.

It defines two primary RPF modes:

*   **Strict Reverse Path Forwarding (Strict RPF):**
    *   **Check:** A packet passes if its source address arrives on the interface that would be used to forward traffic *to* that source address (i.e., the "best reverse path"). This requires a lookup in the Forwarding Information Base (FIB).
    *   **Purpose:** Highly effective for edge networks to prevent spoofing and ensure traceability.
    *   **Limitation:** Requires symmetrical routing (traffic follows the same path in both directions), which is not always true in complex internet topologies.

*   **Loose Reverse Path Forwarding (Loose RPF):**
    *   **Check:** A packet passes if *any* route to its source address exists in the FIB (including default routes). It does *not* check the specific interface.
    *   **Purpose:** Primarily filters "Martian addresses" (unrouted or reserved IPs).
    *   **Limitation:** Sacrifices directionality, making it largely ineffective at ensuring traffic originates legitimately from the connected network. Generally not recommended for filtering between an edge network and an ISP, except for very specific use cases.

**Overall Purpose:** The fundamental goal of RPF is to make IP spoofing more difficult, thereby improving the traceability of attack traffic and protecting networks from various forms of abuse.

### 4.2. Source Code Analysis Findings

**Unicast RPF (`net/ipv4/fib_frontend.c`):**

*   **Core Functions:** `int fib_validate_source(...)` is the public entry point, which calls `static int __fib_validate_source(...)` for the main RPF logic.
*   **`fib_validate_source` Role:** Checks for IPsec protection (RPF ignored if present) and retrieves the `rp_filter` setting for the input device (`IN_DEV_RPFILTER(idev)`).
*   **`__fib_validate_source` Logic:**
    *   Constructs a `flowi4` structure with the packet's source IP (`src`) as the destination (`fl4.daddr`) for a reverse path lookup.
    *   Performs a `fib_lookup` to find the best route to the source IP.
    *   **Strict Mode (`rpf == 1`):**
        *   If `fib_lookup` fails (no route to source), the packet is dropped.
        *   If `fib_lookup` succeeds, it checks if the outgoing device of the *best route to the source* (`fib_info_nh_uses_dev(res.fi, dev)`) matches the *incoming device* of the packet. If not, the packet is dropped.
        *   Also checks for invalid route types (`RTN_UNICAST`, `RTN_LOCAL`).
    *   **Loose Mode (`rpf == 2`):**
        *   Skips the strict mode interface matching check.
        *   Performs a second `fib_lookup` with `FIB_LOOKUP_IGNORE_LINKSTATE` (suggesting it looks for *any* route, even if the link is down).
        *   If this second lookup fails, the packet is dropped.
        *   The key difference from strict mode is that it *only* cares if *a* route exists, not if it's on the correct ingress interface.
    *   **Drop Reason:** RPF failures result in `SKB_DROP_REASON_IP_RPFILTER`.

**Multicast RPF (`net/ipv4/ipmr.c`):**

*   **Distinct Mechanism:** Multicast RPF is handled within `ip_mr_forward` and is distinct from the generic unicast RPF in `fib_frontend.c`. It does not directly call `fib_validate_source`.
*   **Logic:** The core multicast RPF check is a direct comparison: `if (rcu_access_pointer(mrt->vif_table[vif].dev) != dev)`. This checks if the packet arrived on the **expected input interface (the `mfcc_parent` VIF)** for that specific `(S,G)` MFC entry, against the **actual incoming device** of the packet.
*   **No Direct `rp_filter` Sysctl Interaction:** The `rp_filter` sysctl (strict/loose) primarily governs unicast RPF. The multicast RPF check is a more direct "did it come on the right VIF?" check.
*   **Indirect Effect:** If a multicast packet is encapsulated (e.g., in an IPIP tunnel for `VIFF_TUNNEL` VIFs), the *outer unicast header* of that encapsulated packet would be subject to the unicast `rp_filter` rules.
*   **Internal VIFs:** `ipmr_init_vif_indev` (called for internal VIFs like `VIFF_REGISTER` or `VIFF_TUNNEL`) explicitly sets `IPV4_DEVCONF(in_dev->cnf, RP_FILTER) = 0;` for these devices, disabling unicast RPF on them to prevent interference with internal multicast routing mechanisms.

---

## 5. Practical Experimentation Plan



*(This section will be filled in as the experiments are designed and executed, providing verifiable proof of the kernel's RPF behavior.)*



---



## 6. Advanced Use Case: Routing Multicast from an Unroutable Source



A common and challenging real-world scenario arises when needing to route multicast traffic from a device with a hard-coded IP address on an isolated network segment. This directly confronts the core principles of both multicast routing and Reverse Path Filtering.



### 6.1. Use Case Deconstruction



*   **The Source:** A device with a hard-coded IP address (e.g., `192.168.1.100`) on a specific, isolated VLAN (e.g., VLAN 10, subnet `192.168.1.0/24`). This could be a piece of industrial equipment, an embedded sensor, or a video encoder. It sends a multicast stream to a group (e.g., `239.10.20.30`).

*   **The Receiver:** A client (e.g., a monitoring station) on a completely different VLAN and subnet (e.g., VLAN 20, subnet `10.0.20.0/24`).

*   **The Router:** A Linux machine acting as a router between these two VLANs. It has an interface in VLAN 10 (e.g., `eth0.10` with IP `192.168.1.1`) and an interface in VLAN 20 (e.g., `eth0.20` with IP `10.0.20.1`).

*   **The Goal:** The client on VLAN 20 needs to receive the multicast stream from the device on VLAN 10.



### 6.2. The Core Problems: RPF Failure and SNAT Ambiguity







This setup creates two fundamental and interacting problems for our Linux router.







#### Problem 1: Reverse Path Filtering (RPF) Failure







When the multicast packet from the unroutable source `192.168.1.100` arrives at the router, the kernel's RPF check is triggered. Because the router has no route back to this source, the check fails, and the packet is dropped. This happens regardless of whether `rp_filter` is in `strict` or `loose` mode.







#### Problem 2: SNAT Target Ambiguity with Multiple Receivers







If we expand the scenario to include multiple receiver VLANs (e.g., VLAN 20, 30, and 40), a simple Source NAT (SNAT) in the `prerouting` chain is no longer sufficient. The `prerouting` hook is processed *before* the routing decision is made. At this stage, the kernel doesn't know which of the multiple output interfaces the packet will be sent to. We cannot create a rule that says "SNAT to the IP of VLAN 20 for packets going to VLAN 20, and to the IP of VLAN 30 for packets going to VLAN 30," because the routing decision hasn't happened yet. A single `snat to 10.0.20.1` rule would send incorrectly sourced packets to the other VLANs.







### 6.3. Solutions















#### Solution 1: The "Correct" Routing Fix (Often Not Possible)















*   **Method:** Add a route on the Linux router that makes the source IP reachable (`sudo ip route add 192.168.1.0/24 dev eth0.10`).







*   **Why it works:** This satisfies the RPF check on the router.







*   **Problem:** This is often not a complete solution, as the downstream clients on the receiver VLAN still have no route back to the source, which can cause issues for some applications. It also may not be desirable to advertise these isolated networks.















#### Solution 2: The Pragmatic RPF Workaround (Disabling `rp_filter`)















*   **Method:** Disable RPF on the incoming interface of the router (`sudo sysctl -w net.ipv4.conf.eth0.10.rp_filter=0`).







*   **Why it works:** This simply turns off the check, allowing the packet to be processed.







*   **Problem:** This is a security risk, as it disables spoofing protection on that interface. It should be done with caution.















#### Solution 3: The Advanced Fix - Source NAT with `nftables` (Recommended)















This is the most robust and elegant solution. It fixes the RPF problem without disabling security and without requiring routing changes on the client networks.















*   **Method:** Use `nftables` on the router to change the source address of the multicast stream as it is being routed. The packet's source is changed to be the router's own IP on the outgoing interface.







*   **`nft` Ruleset:**







    ```







    # Add a new table and chain for prerouting mangle







    nft add table ip mangle







    nft add chain ip mangle prerouting { type filter hook prerouting priority -150 \; }















    # Add the rule to perform the Source NAT







    nft add rule ip mangle prerouting iifname "eth0.10" ip saddr 192.168.1.100 ip daddr 239.10.20.30 snat to 10.0.20.1







    ```







*   **Why it works:**















    1.  The multicast packet arrives on `eth0.10`.







    2.  The packet is processed by the `prerouting` Netfilter hook *before* the kernel performs a routing lookup.







    3.  The `nftables` rule in the `mangle` table changes the source IP from the unroutable `192.168.1.100` to the routable `10.0.20.1`.







    4.  After the `prerouting` hook finishes, the kernel proceeds to the routing stage (`ip_rcv_finish`).







    5.  The unicast RPF check is performed on the *new, translated* source, `10.0.20.1`. Since this is a local IP on the router, the RPF check passes trivially.







    6.  The multicast routing daemon (which must be configured to expect the *translated* source) forwards the packet.







    7.  The packet is forwarded to the client network, appearing to come from a legitimate, routable source (the router itself).







*   **Benefit:** This is the cleanest solution. It contains the complexity to the router, requires no changes on the clients, and leaves RPF enabled for all other traffic.















### 6.4. Architectural Evaluation: `PREROUTING` vs. `POSTROUTING` SNAT















For the multi-egress scenario, a simple `PREROUTING` SNAT to a single egress IP is insufficient, as it sends incorrectly sourced packets to all but one VLAN. A more advanced proposal is to use `PREROUTING` to SNAT the unroutable source to a stable, routable loopback IP on the router. This is a technically viable solution that solves the RPF check without disabling `rp_filter`. However, it introduces significant architectural trade-offs.















The table below compares the two viable solutions: `PREROUTING` SNAT to a loopback IP vs. `POSTROUTING` SNAT to the egress interface IP.















| Feature | `PREROUTING` Loopback SNAT | `POSTROUTING` Egress SNAT (Recommended) |







| :--- | :--- | :--- |







| **RPF Solution** | **Yes (passes trivially)** | **No (requires `rp_filter=0` on ingress)** |







| **Routing Changes** | **Yes (requires advertising the loopback IP to all clients)** | **No (self-contained on the router)** |







| **Source IP for Clients** | Same for all clients (e.g., `172.16.0.1`) | Local to each client's subnet (e.g., `10.0.20.1`, `10.0.30.1`) |







| **Architectural Complexity** | Shifts complexity to the downstream routing domain. | Keeps complexity contained on the router. |







| **Network Cleanliness** | Less clean. Clients see a "magic" source IP from a different subnet. | Cleaner. Clients see their local gateway as the source, which is a standard pattern. |















**Conclusion and Recommendation:**















While the `PREROUTING` to a loopback approach works, it creates an external dependency, forcing all client networks to be aware of a special "service IP." The `POSTROUTING` approach, while requiring a targeted relaxation of `rp_filter` on the single ingress interface, is architecturally superior. It is a **self-contained solution** that presents a clean, conventional network view to the downstream clients. For a robust and maintainable system, the `POSTROUTING` SNAT solution is preferable.















### 6.5. Hypothesis-Driven Experimental Plan































To properly evaluate the competing solutions, we will treat them as formal hypotheses and design a multi-stage experiment to test the claims of each one. The experiments will be ordered to test for success first, which makes the final control experiment's failure mode less ambiguous. A failure to receive packets could be for many reasons; by proving the test harness works with two different solutions first, we can be more confident that the control failure is due to RPF.































#### Hypothesis A: The `POSTROUTING` SNAT Approach































*   **Claim:** This approach can successfully forward multicast from an unroutable source to multiple egress subnets.















*   **Predicted Pros:** The solution is self-contained on the router. Each client subnet receives packets from a source IP local to their subnet.















*   **Predicted Cons:** It requires disabling `rp_filter` on the ingress interface, a targeted security reduction.















*   **Mechanism:** `rp_filter=0` on ingress + `nftables` SNAT in the `postrouting` hook.































#### Hypothesis B: The `PREROUTING` Loopback SNAT Approach































*   **Claim:** This approach can also successfully forward the multicast stream.















*   **Predicted Pros:** It works without disabling `rp_filter`, preserving default spoofing protection.















*   **Predicted Cons:** It pushes complexity downstream, requiring all client networks to have a route back to the router's loopback IP. All clients see the same, non-local source IP.















*   **Mechanism:** `rp_filter=1` on ingress + `nftables` SNAT in the `prerouting` hook to a routable loopback IP.































#### Experimental Order































The functional test (`tests/test_rpf_scenario.py`) will be structured to run three experiments in the following order:































**1. Experiment 1: Test Hypothesis A (`POSTROUTING` Solution)**















*   **Objective:** Verify the functionality and side effects of the `POSTROUTING` solution.















*   **Setup:**















    *   Create a "router," "source," and two "receiver" namespaces.















    *   Enable `rp_filter=1` on all router interfaces initially.















*   **Action:**















    1.  Set `rp_filter=0` on the router's ingress interface only.















    2.  Install the `nftables` `postrouting` SNAT rule.















    3.  Add the multicast route `(192.168.1.100, 239.10.20.30)` via the `mfc_daemon`.















    4.  Send the multicast stream from the source.















*   **Expected Outcome:** **Success.**















    *   Packets are received in **both** receiver namespaces.















    *   The source IP in receiver-20's packet is the router's IP on that subnet.















    *   The source IP in receiver-30's packet is the router's IP on that subnet.































**2. Experiment 2: Test Hypothesis B (`PREROUTING` Solution)**















*   **Objective:** Verify the functionality and side effects of the `PREROUTING` loopback solution.















*   **Setup:** A clean setup, identical to the initial state of Experiment 1.















*   **Action:**















    1.  Keep `rp_filter=1` on all interfaces.















    2.  Configure a loopback IP (e.g., `172.16.0.1/32`) on the router.















    3.  Add routes in both receiver namespaces pointing back to the loopback IP via the router.















    4.  Install the `nftables` `prerouting` SNAT rule targeting the loopback IP.















    5.  Add the multicast route for the *translated* source: `(172.16.0.1, 239.10.20.30)`.















    6.  Send the multicast stream from the source.















*   **Expected Outcome:** **Success.**















    *   Packets are received in **both** receiver namespaces.















    *   The source IP in **both** packets is the loopback IP (`172.16.0.1`).































**3. Experiment 3: The Control (Baseline Failure)**















*   **Objective:** Prove that the default RPF settings are the specific cause of failure.















*   **Setup:** A clean setup, identical to the initial state of the previous experiments.















*   **Action:**















    1.  Keep `rp_filter=1` on all interfaces.















    2.  Do NOT install any `nftables` rules.















    3.  Add the original multicast route `(192.168.1.100, 239.10.20.30)`.















    4.  Send the multicast stream.















*   **Expected Outcome:** **Failure.** No packets are received in either receiver namespace.































This experimental structure will provide clear, unambiguous evidence to evaluate the trade-offs of each approach.




























