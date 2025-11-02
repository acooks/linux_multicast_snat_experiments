# Experiment Log: Tracing Multicast and Bypassing RPF

## 1. Objective

This document serves as the official log and "lab notebook" for the series of experiments conducted to answer a single, core question: **Can an `nftables` rule in the `prerouting` hook modify a multicast packet's source address *before* the kernel's Reverse Path Filtering (RPF) check drops it?**

This log details the journey from initial flawed assumptions and failed tests to a final, successful, and evidence-based conclusion.

---

## 2. The Experimental Arc: A Summary

Our investigation followed a classic, if painful, scientific process:

1.  **Initial Hypothesis & Flawed Methodology:** We began with the correct hypothesis (that `prerouting` SNAT could bypass RPF) but used a completely flawed set of diagnostic tools (`dmesg`, `nft monitor log`, `dummy` interfaces). This led to a series of confusing and contradictory failures.
2.  **Ground Truth - The First Breakthrough:** We discovered that `nft monitor trace` was the only reliable tool for observing Netfilter events. We then conducted a foundational "positive confirmation" test (`test_single_ip_dummy_ping_is_traced.py`, now deleted) which, after much trial and error, succeeded.
3.  **Key Insight from "Ground Truth":** The successful test taught us a critical, non-obvious piece of kernel behavior: a `ping` to a local IP, even one on a `dummy` interface, is routed over the **loopback (`lo`) interface**. This discovery was the key to making the first test pass and informed all subsequent test design.
4.  **Formalized, Progressive Test Suite:** Armed with a reliable diagnostic tool and a better understanding of kernel behavior, we designed a formal, progressive test suite (documented in `TEST_PLAN.md`) to build our case from the ground up, isolating one variable at a time.
5.  **Execution and Final Conclusion:** We executed the test suite, with each test providing a clear, unambiguous result, leading to our final conclusion.

---

## 3. The Test Suite: Execution Records and Findings

This section details the outcome and lessons learned from each test in the formal suite.

### Test 1: Baseline Unicast Trace

*   **File:** `tests/test_veth_trace.py`
*   **Status:** **Completed and Passing**
*   **Purpose:** To prove that our diagnostic harness (`nft monitor trace`) works correctly for a simple **unicast** packet (`ping`) traversing a `veth` pair between two namespaces.
*   **Findings:** This test passed on the first attempt. It confirmed that the methodology developed in our initial "ground truth" test was portable to a more realistic, two-namespace `veth` environment. This gave us confidence to proceed to multicast.

### Test 2: Baseline Multicast Trace

*   **File:** `tests/test_multicast_trace.py`
*   **Status:** **Completed and Passing**
*   **Purpose:** To prove that our diagnostic harness also works for a **multicast** packet sent from a **routable** source.
*   **Findings:** This test also passed on the first attempt. It confirmed that, from a Netfilter `prerouting` perspective, a multicast packet from a routable source behaves identically to a unicast packet, hitting the hook as expected.

### Test 3: Prove RPF Failure (The Control Case)

*   **File:** `tests/test_rpf_failure.py`
*   **Status:** **Completed and Passing**
*   **Purpose:** To definitively prove that the kernel's RPF check **does** drop a multicast packet from an **unroutable** source.
*   **Findings:** This test passed and was a critical success. The `nft monitor trace` output showed the packet hitting the `prerouting` hook, but **not** the `input` hook. This was the first piece of direct, empirical evidence that the RPF drop happens *after* `prerouting`, which is the foundational principle our final experiment relies on.

### Test 3b: The RPF Pass "Positive Control"

*   **File:** `tests/test_rpf_pass.py`
*   **Status:** **Completed and Passing**
*   **Purpose:** To prove that a multicast packet from a **routable** source **passes** the RPF check and reaches the `input` hook.
*   **Findings - The "Listener" Breakthrough:** This test initially failed in a very informative way. The packet hit `prerouting` but not `input`, even with a routable source. This forced us to confront a deeper aspect of multicast handling: the kernel will not deliver a multicast packet locally (to the `input` hook) unless a process has explicitly joined the multicast group **on that specific interface**. Our initial use of `netcat` was ambiguous.
*   **What We Wish We Knew Yesterday:** The simple `nc -l <mcast_group>` command is not sufficient to reliably join a multicast group for testing.
*   **The Fix:** We created a dedicated Python script, `listen_multicast.py`, which uses the `socket.IP_ADD_MEMBERSHIP` option to unambiguously join the group on the correct interface. Once we replaced `nc` with this script, the test passed. This provided the definitive "positive control" for RPF behavior.

### Test 4: The SNAT RPF Bypass

*   **File:** `tests/test_multicast_snat_rpf.py`
*   **Status:** **Completed and Conclusively Failed**
*   **Purpose:** To test the primary hypothesis: that an `nftables` SNAT rule in the `prerouting` hook can "fix" an unroutable packet, allowing it to bypass the RPF check.
*   **Findings - The Definitive Conclusion:** This final experiment provided the definitive answer to our core question. The test failed at the rule-loading stage, with the kernel returning an unambiguous **"Operation not supported"** error.
*   **The Root Cause Analysis:** Our initial interpretation of this error was incorrect. After a deep dive into the kernel source, the true reason was located in the connection tracking subsystem (`linux/net/netfilter/nf_conntrack_core.c`). This subsystem, which is a mandatory prerequisite for the NAT engine to function, contains an explicit check that **refuses to create a connection tracking entry for any incoming multicast packet**.
*   **The Final Answer:** Because an incoming multicast packet can never be "tracked," the NAT engine cannot operate on it. The `nftables` framework recognizes this contradiction and correctly rejects any `snat` rule that matches on a multicast destination address at rule-loading time. The technical disagreement is therefore settled: **the proposed solution is not viable because the Linux kernel's Netfilter architecture fundamentally does not support NAT for incoming multicast traffic.**

---

## 5. Final Consolidated Lessons Learned

1.  **The Right Tool:** `nft monitor trace` is the only reliable way to trace a packet's path through Netfilter.
2.  **The `lo` Interface is Special:** Packets sourced and destined to the same host are routed over the `lo` interface.
3.  **Multicast Requires a Listener:** The kernel will not process a multicast packet locally unless a process has explicitly joined the group on the ingress interface.
4.  **RPF Happens After Prerouting:** We have empirically proven that the RPF check occurs *after* the `prerouting` hook.
5.  **No NAT for Incoming Multicast:** The Netfilter connection tracking subsystem, and by extension the NAT engine, explicitly refuses to operate on incoming multicast packets. This is a fundamental design principle, not a bug.

This log provides a complete record of our journey and a solid, evidence-based conclusion.
