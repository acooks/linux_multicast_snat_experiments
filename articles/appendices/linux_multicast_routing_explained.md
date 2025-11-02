# Understanding Linux Multicast Routing

## 1. The Core Principle: A Split System

Linux multicast routing is built on a fundamental separation of concerns between the kernel (the **data plane**) and a userspace application (the **control plane**). Understanding this division is the key to mastering multicast on Linux.

*   **The Kernel (Data Plane):** The kernel acts as a high-performance but passive forwarding engine. It contains the machinery to duplicate and route multicast packets at line rate but has no built-in intelligence to decide where those packets should go. It follows the rules it is given and drops everything else.

*   **Userspace (Control Plane):** A userspace daemon is the "brain" of the operation. It contains the policy and logic, deciding which multicast streams should be routed from where to where. It is solely responsible for programming the kernel's forwarding engine with the correct set of rules.

Without an active control plane daemon, the kernel will **not** route multicast traffic between subnets, even if all interfaces are correctly configured.

---

## 2. The Kernel's Data Plane Engine

The kernel's forwarding engine has two primary components: the Multicast Forwarding Cache (MFC) and Virtual Interfaces (VIFs).

### The Multicast Forwarding Cache (MFC)

The MFC is the kernel's main lookup table for routing multicast packets. For every incoming multicast packet, the kernel consults the MFC to find a matching rule. An MFC entry, or "mroute", is a simple but powerful rule:

> **If a packet from `(Source IP, Group IP)` arrives on `Input_VIF`, then forward copies of it to `Output_VIF_1`, `Output_VIF_2`, etc.**

*   An `(S,G)` route is a **source-specific** route, identified by both a source and group address.
*   A `(*,G)` route is an **any-source** route, where the source is a wildcard (`0.0.0.0`). The kernel represents this by setting the source address field in the MFC entry to `INADDR_ANY`.

### Virtual Interfaces (VIFs)

The MFC does not operate on network devices like `eth0` directly. Instead, it uses an abstraction called a **Virtual Interface (VIF)**. A VIF is a logical routing endpoint created by the control plane daemon. Each VIF is given a unique index and is mapped to a real network device.

Creating a VIF has several prerequisites:
1.  **`IFF_MULTICAST` Flag:** The underlying physical device must have its multicast flag enabled (`ip link set dev <if> multicast on`).
2.  **Local Address:** The VIF must be anchored to a valid IP address belonging to the underlying physical device.

### The Reverse Path Forwarding (RPF) Check

The RPF check is the kernel's primary loop-prevention and security mechanism. For every incoming multicast packet, the kernel asks:

> "Did this packet from `Source IP` arrive on the same interface I would use to send a unicast packet *back to* that `Source IP`?"

To answer this, the kernel performs a lookup in the standard unicast routing table for the packet's source address. If the interface for that unicast route does not match the interface the multicast packet arrived on, the packet is dropped.

---

## 3. The Userspace Control Plane

The intelligence for multicast routing resides entirely in a userspace daemon. This daemon is **absolutely required** for multicast routing to function.

### The Daemon's Role

The daemon's job is to learn the desired multicast routing policy and program the kernel's MFC accordingly. Critically, the kernel's multicast state is tied to the lifecycle of the socket that initializes it. The control plane application **must run as a persistent daemon**; if it simply adds a route and exits, the kernel will automatically clean up and remove the route.

There are two main types of daemons:

*   **Static Daemons (e.g., `smcroute`):** These daemons read a configuration file at startup and install a fixed set of routes into the MFC. They are simple and effective for stable networks where multicast paths do not change.
*   **Dynamic Daemons (e.g., `pimd`):** These daemons implement a dynamic routing protocol like PIM-SM. They communicate with other routers to discover network topology and listen for IGMP reports from local hosts to learn about group memberships. They continuously update the kernel's MFC based on this real-time information.

---

## 4. The Kernel APIs: A Tale of Two Interfaces

A userspace daemon can communicate with the kernel's multicast subsystem via two different APIs. Understanding the distinct purpose of each is crucial.

### The Legacy `setsockopt` API: The Write Path

The proven and correct way to **add, change, or delete** multicast routes in the MFC is the legacy `setsockopt` API. This is the interface used by production daemons like `smcroute` and `pimd`.

The process works as follows:
1.  **Create Socket:** Open a raw socket: `socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)`.
2.  **Gain Control (`MRT_INIT`):** Call `setsockopt` with `MRT_INIT`. This is a privileged operation requiring `CAP_NET_ADMIN` that activates the multicast engine and registers the socket as the "master" controller for a routing table.
3.  **Define Interfaces (`MRT_ADD_VIF`):** Create VIFs by passing `struct vifctl` objects to `setsockopt`.
4.  **Program Routes (`MRT_ADD_MFC`):** Add forwarding entries to the MFC by passing `struct mfcctl` objects to `setsockopt`.
5.  **Release Control (`MRT_DONE`):** When the daemon exits, it calls `MRT_DONE` to signal the kernel to tear down all associated VIFs and MFC entries.

This API is direct, performant, and provides the necessary control for writing to the MFC. It also provides a mechanism for the kernel to send **upcall messages** to the daemon (e.g., for a cache miss) by queuing a raw IGMP message on the same socket.

### The `rtnetlink` API: The Read Path

The modern `rtnetlink` API is the standard, unified interface for nearly all networking configuration in Linux. However, its role in multicast routing is nuanced.

*   **Reading the MFC:** `rtnetlink` is the correct and standard way to **read or dump** the contents of the MFC. This is exactly what the `ip mroute show` command does. It sends an `RTM_GETROUTE` message and filters the results for routes of type `RTN_MULTICAST`.

*   **The "Write" Problem:** Attempting to add a multicast route using `rtnetlink` (`RTM_NEWROUTE` with `rtm_type = RTN_MULTICAST`) will appear to succeed, but **it will not create a functional MFC entry.**

**Why?** Kernel source analysis reveals a crucial architectural split:
*   `RTM_NEWROUTE` messages are handled by the generic **FIB (Forwarding Information Base) subsystem** (`net/ipv4/fib_frontend.c`). This subsystem manages the main unicast routing tables. It sees `RTN_MULTICAST` as a valid route type and adds an entry to its own tables, but it never communicates with the multicast engine.
*   The actual multicast engine, the **IPMR (IP Multicast Routing) subsystem** (`net/ipv4/ipmr.c`), is completely separate and is only programmed via the legacy `setsockopt` API.

Therefore, the two APIs have distinct, non-overlapping roles for multicast management:
*   **Use `setsockopt` to write.**
*   **Use `rtnetlink` to read.**

---

## 5. Practical Considerations

### Verification

The authoritative command to view the kernel's true MFC state is `ip mroute show`. If a route does not appear in this command's output, it is not correctly installed in the data plane.

### Security

Control over the MFC is a privileged operation. The kernel enforces this with a two-tiered security model:
1.  The initial `MRT_INIT` call requires the `CAP_NET_ADMIN` capability.
2.  Once a socket is registered via `MRT_INIT`, that specific socket is permitted to make further changes without the capability. Any other process attempting to modify the MFC must have `CAP_NET_ADMIN`.

### Isolated Testing

Testing multicast routing should always be done in an isolated environment. Network namespaces, combined with virtual Ethernet (`veth`) pairs, provide a lightweight and effective way to create a completely self-contained network stack for safe experimentation.
