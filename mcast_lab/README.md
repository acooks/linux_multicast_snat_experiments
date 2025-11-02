# Multicast Lab Environment

This directory contains the empirical lab environment that underpins the findings in **[The Definitive Guide to Debugging Linux Multicast](../articles/the_definitive_guide_to_linux_multicast_debugging.md)**. It provides a set of isolated experiments designed to prove how the Linux kernel handles multicast routing, Netfilter, and Reverse Path Forwarding (RPF).

## Structure

-   **`/src`**: Contains helper scripts and tools:
    -   `listen_multicast.py`: A simple Python script to listen for multicast traffic within a network namespace.
    -   `mfc_c_test.c`: A C program demonstrating how to directly program the kernel's Multicast Forwarding Cache (MFC) using the legacy `setsockopt` API. This is the "ground truth" reference for direct kernel interaction.
    -   `run_experiment_instructive.py`: A Python script that orchestrates a full experiment, including network namespace setup, `pymfcd` daemon startup, and MFC rule injection, mirroring the final solution discussed in the guide.
    -   `pymfcd_vendored/`: A vendored copy of the `pymfcd` library, used by `run_experiment_instructive.py` to interact with the kernel's MFC.
-   **`/tests`**: Contains the `pytest` test suite. Each file represents a specific, isolated experiment designed to prove a hypothesis about kernel behavior, as detailed in the main guide.

## Running the Experiments

All experiments, whether Python-based `pytest` scripts or the C reference implementation, require root privileges to manipulate network namespaces and kernel parameters.

### Prerequisites

-   Python 3
-   `pytest`
-   `pyroute2`
-   `cffi`
-   `make` (for the C example)
-   `gcc` (for the C example)

### Installation

It is recommended to use a Python virtual environment. From the project root directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Running the `pytest` Suite

To run the entire suite of experiments, execute `pytest` from this directory with `sudo`:

```sh
sudo pytest
```

You can also run a specific test file, for example, to reproduce the RPF failure:

```sh
sudo pytest tests/test_rpf_failure.py
```

### Compiling and Running the C MFC Example

To compile and run the `mfc_c_test.c` reference implementation:

1.  Navigate to the `src` directory:
    ```sh
    cd src
    ```
2.  Compile using `make`:
    ```sh
    make mfc_c_test
    ```
3.  Run the compiled executable. You will need to provide the input and output interface indices. For example, if you have a network namespace with `veth-in-p` (index 10) and `veth-out-p` (index 11):
    ```sh
    sudo ./mfc_c_test 10 11
    ```
    (Note: This requires a pre-configured network namespace with the specified interfaces. The `run_experiment_instructive.py` script can help set up such an environment.)