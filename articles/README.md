# Articles: A Journey into the Linux Multicast Labyrinth

This directory contains the narrative output of the investigation. The content is structured as a series of articles intended to be read in order, forming a multi-part blog series.

## Suggested Reading Order

1.  **[The Case of the Disappearing Multicast Packet](./01_the_debugging_journey.md)**: A story-driven walkthrough of the debugging process, starting with a mysterious packet drop and ending with a deep dive into the kernel's netfilter and connection tracking subsystems.

2.  **[Linux Multicast Routing Demystified: The Two-API Reality](./02_the_two_api_reality.md)**: A foundational guide to the architecture of Linux multicast, focusing on the critical (and non-obvious) split between the modern `rtnetlink` API for reading state and the legacy `setsockopt` API for writing it.

3.  **[Hitting the Wall: Why Kernel Multicast Doesn't Scale (And What We Use Instead)](./03_scaling_limitations_and_sdn.md)**: An architectural discussion of the `MAXVIFS=32` limitation in the kernel's native multicast data plane and an exploration of modern SDN-based solutions (like Open vSwitch and EVPN) that bypass it.

## Appendices

The `/appendices` directory contains the raw "lab notebook" materials, including detailed experiment logs, test plans, and topic-specific deep-dive notes that were consolidated into the final articles.
