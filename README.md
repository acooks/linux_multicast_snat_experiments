# Linux Multicast Routing & Netfilter: The Definitive Guide

This repository documents a deep-dive investigation into a common, yet challenging, networking problem: **how to forward multicast traffic from a source with an unroutable, unchangeable IP address (e.g., a black-box video camera) to multiple destinations, overcoming Linux kernel limitations like Reverse Path Forwarding (RPF) and the inability to perform Source NAT (SNAT) on incoming multicast packets.**

Our journey revealed that while `nftables` SNAT is architecturally impossible for incoming multicast (due to its reliance on the `conntrack` subsystem, which explicitly ignores multicast), the problem can be solved by directly programming the kernel's Multicast Forwarding Cache (MFC) via its legacy `setsockopt` API.

## The Definitive Guide

All the findings, experimental methodology, and the final solution are consolidated into a single, comprehensive article:

*   **[The Definitive Guide to Debugging Linux Multicast](articles/the_definitive_guide_to_linux_multicast_debugging.md)**

This guide walks you through the entire debugging process, from learning how to observe kernel packet flow with `nft monitor trace`, to understanding the RPF check's behavior, to implementing the correct solution using direct MFC manipulation.

## Repository Structure

-   **`/articles`**: Contains the primary output of this project: the definitive long-form guide. All other preliminary articles have been consolidated into this single document.
-   **`/mcast_lab`**: A self-contained, reusable lab environment for conducting the experiments described in the guide. It uses Python, `pytest`, and network namespaces to create isolated testbeds for multicast and Netfilter behavior, empirically proving the guide's assertions.

## Quick Start: Running the Experiments

To run the experiments and verify the findings yourself, navigate to the `mcast_lab` directory.

```sh
cd mcast_lab
```

It is recommended to use a Python virtual environment.

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r ../requirements.txt
```

You can then run the full test suite:

```sh
sudo pytest
```