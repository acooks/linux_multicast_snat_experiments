# Test Plan: RPF and Multicast Forwarding Experiments

## 1. Objective

The purpose of this test suite is to empirically verify the interaction between `nftables`, multicast packets, and the Linux kernel's Reverse Path Filtering (RPF) check. We will use a progressive suite of atomic tests to build a clear, evidence-based understanding of the kernel's behavior.

## 2. Core Methodology

All tests will be implemented as Python `pytest` scripts. The core tools used are:
*   **Isolation:** Network namespaces to create independent, virtual network stacks.
*   **Connectivity:** Virtual Ethernet (`veth`) pairs to connect namespaces.
*   **Instrumentation:** `nftables` to install logging and NAT rules on Netfilter hooks.
*   **Verification:** `nft monitor trace` as the definitive tool for observing a packet's journey through the Netfilter framework.

---

## 3. The Test Suite

The suite is designed to build upon previous successes, isolating one variable at a time.

### Test 1: Baseline Unicast Trace

*   **File:** `tests/test_veth_trace.py`
*   **Status:** **Completed and Passing**
*   **Purpose:** To prove that our diagnostic harness (`nft monitor trace`) works correctly for a simple **unicast** packet (`ping`) traversing a `veth` pair between two namespaces. This establishes the foundation for all subsequent tests.
*   **Hypothesis:** A standard `ping` between two namespaces will have its path through the `prerouting` and `input` hooks successfully traced.
*   **Setup:** Two namespaces (`ns-source`, `ns-router`) connected by a `veth` pair.
*   **Action:** `ns-source` sends a single `ping` to `ns-router`.
*   **Expected Outcome:** The `nft monitor trace` output in `ns-router` must contain the log prefixes from both the `prerouting` and `input` hooks.

### Test 2: Baseline Multicast Trace

*   **File:** `tests/test_multicast_trace.py`
*   **Status:** **Completed and Passing**
*   **Purpose:** To prove that our diagnostic harness also works for a **multicast** packet sent from a **routable** source. This isolates the "multicast" variable.
*   **Hypothesis:** A standard multicast packet from a known, routable source will be successfully traced hitting the `prerouting` hook in the receiving namespace.
*   **Setup:** Two namespaces (`ns-source`, `ns-router`) connected by a `veth` pair.
*   **Action:** `ns-source` sends a single UDP multicast packet from its main, routable `veth` IP address.
*   **Expected Outcome:** The `nft monitor trace` output in `ns-router` must contain the log prefix from the `prerouting` hook.

### Test 3: Prove RPF Failure (The Control Case)

*   **File:** `tests/test_rpf_failure.py`
*   **Status:** **Completed and Passing**
*   **Purpose:** To definitively prove that the kernel's RPF check **does** drop a multicast packet from an **unroutable** source, as theory predicts. This establishes our "control" failure case.
*   **Hypothesis:** A multicast packet from an unroutable source will be dropped by the kernel's RPF check *after* the `prerouting` hook but *before* the `input` hook.
*   **Setup:** Two namespaces with a `veth` pair. `ns-router` will have strict RPF enabled (`rp_filter=1`).
*   **Action:** `ns-source` sends a UDP multicast packet from a secondary, unroutable IP address.
*   **Expected Outcome:** The `nft monitor trace` output in `ns-router` must contain the log prefix from the `prerouting` hook, but **must not** contain the log prefix from the `input` hook.

### Test 3b: RPF Pass (Positive Control)

*   **File:** `tests/test_rpf_pass.py`
*   **Status:** **Completed and Passing**
*   **Purpose:** To prove that a multicast packet from a **routable** source **passes** the RPF check and reaches the `input` hook, serving as a positive control.
*   **Hypothesis:** With a listener correctly joined to the multicast group on the ingress interface, a routable multicast packet will pass the RPF check and be delivered locally.
*   **Setup:** Two namespaces with a `veth` pair and strict RPF enabled. A dedicated Python script (`listen_multicast.py`) is used to listen on the correct interface in `ns-router`.
*   **Action:** `ns-source` sends a single UDP multicast packet from its main, routable `veth` IP address.
*   **Expected Outcome:** The `nft monitor trace` output in `ns-router` must contain the log prefixes from **both** the `prerouting` and `input` hooks.
*   **Finding:** This test was critical, as it proved that a listener must explicitly join the group on the correct interface for the kernel to deliver the packet to the `input` hook.

### Test 4: The SNAT RPF Bypass

*   **File:** `tests/test_multicast_snat_rpf.py`
*   **Status:** **Completed and Conclusively Failed**
*   **Purpose:** To test the primary hypothesis: that an `nftables` SNAT rule in the `prerouting` hook can "fix" an unroutable packet, allowing it to bypass the RPF check.
*   **Hypothesis:** An `nftables` SNAT rule in `prerouting` will modify the packet's source IP. The subsequent RPF check will evaluate this new, routable source IP and pass the packet.
*   **Setup:** A rigorous, multi-stage tracing setup with a dedicated `nat` table for the SNAT operation and a `filter` table for post-NAT observation.
*   **Outcome:** The test failed because the `nft` command returned an "Operation not supported" error directly from the kernel when attempting to load the SNAT rule for a multicast destination.
*   **Finding:** This provides the definitive answer to our core question. The Linux kernel's Netfilter `nat` engine **does not support performing SNAT on packets with a multicast destination address.** Therefore, this method cannot be used to bypass the RPF check.

---