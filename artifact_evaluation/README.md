# rose Artifact Evaluation

This document describes the content of this repo, which contains all materials need to build and execute all experiments in the paper "Rose: Reproducing External-Fault-Induced Failures in Distributed Systems with Lightweight Instrumentation", accepted at Eurosys 2026.
# Overview

```
artifact_evaluation
│   prepare_vms.sh                   - Prepares the necesssary VMs to run the experiments
│   reproduce_bugs.sh                - Reproduces the bugs displayed in Table 1
|   reproduce_tracing_tests.sh       - Reproduces the tracing tests displayed in Table 2
│   reproduce_heuristics_tests.sh    - Reproduces the heuristics tests displayed in Table 3
|   kick_the_tires.sh                - Runs a subset of tests to confirm the correct setup of the environment.
|   requirements.sh                  - Checks if the machine has the necessary requirements to run AE.
|
└─── bug_reproduction           - Contains the script and the setup of bug reproduction tests
└─── heuristics_effectiveness   - Contains the script and the setup  of the heuristics tests
└─── tracing_overhead           - Contains the comparison of different types of tracing
      └─── throughput           - Contains the scripts and setup for the throughput overhead tests
      └─── trace_size           - Contains the scripts and setup for the comparison of trace sizes
└─── scripts                    - Scripts to setup the environment for AE
```

# Requirements

Rose was built and tested in Ubuntu 24.03.5 LTS, requires vagrant (tested for version 2.4.9, but any modern version should suffice), VirtualBox (tested for 7.1.7, but any modern version should suffice) as a vagrant provider and Python (3.12.3) for scripts.

The script `requirements.sh` will check for suitability and install the requirements.


# Setup

Before starting the evaluation:

- Clone the repository https://github.com/sebastiaoamaro/rose

```
~/$ git clone https://github.com/sebastiaoamaro/rose
~/$ git submodule update --init --recursive
```

# MacOS

If you are using MacOS your CPU architecture might not be x86_64, Intel/AMD 64-bit, this can cause problems in vagrant leveraging VirtualBox as a provider. Thus, VMware is required. Install VMware workstation by following the steps in: [VMware](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion).
After, run this script to set up the vmware vagrant plugin/utility:

```
~/$ ./rose/artifact_evaluation/prepare_vmware.sh
```

**Now set a environment variable to point to the appropriate Vagrantfile, rerun on every new shell:**

```
~/rose $ export VAGRANT_VAGRANTFILE=/*fill accordingly*/rose/Vagrantfile.vmware
```

**Due to VMware not supporting shared folders, please run this script after the experiments, run it from the rose directory:**

```
~/rose/$ ./artifact_evaluation/collect_results.sh
```

# Building the Environment

The following commands builds every necessary artifact required for the evaluation. See below for time estimations.
Three different virtual machines will be built. One to reproduce the SCF bugs, one for systems using docker, and one for systems using LXC (this one will also be used to run the tracing/heuristics tests).

```
~/$ cd rose/artifact_evaluation 
~/rose/artifact_evaluation/$ ./prepare_vms.sh
```

During this step the virtual  machines may ask for grub related questions, simply say yes when possible or press enter (when it is the only option) and the installation will go smoothly.

Breakdown of building time: 1~2 hours

# Kick-the-tires Evaluation - Short Tests

To ensure everything is working properly, without waiting for long experiments, follow these steps to perform the reproduction of a small subset of bugs, and a fast tracing-overhead test.

```
~/rose/artifact_evaluation/$ ./kick_the_tires.sh
```

Breakdown of run time: 1~2 hours

**If using VMware run the collect_results.sh script**

### Reproduced Bugs

- (Table 1): Bugs reproduced by rose
 
```
~/rose/artifact_evaluation/$ ./display_bug_table.sh kick
```

### Overhead of Tracer

- (Table 2 ): Cost of rose tracer versus other alternatives

```
~/rose/artifact_evaluation/$ ./display_tracing_table.sh
```

- Now you can proceed to the full evaluation described in the appendix.
