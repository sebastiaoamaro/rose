# rose

This document describes the content of this repo, the source code for rose, as described in "rose: Reproducing External-Fault-Induced Failures in Distributed Systems with Lightweight Instrumentation", accepted to EuroSys 2026.

# Overview

```
rose
│   reproduction.py         - Entry point to reproduce a bug
│   profiler.py             - Profiles a bug_reproduciton (see bug_reproductions), and removes functions which are called more than X times per second
│   parse.py                - Parses a schedule
|   run_schedule.sh         - Runs a schedule
└─── profiler               - Implements the Profiler componenet as detailed in the paper (Section 4.2 and 5.1)
└─── tracer                 - Implements the Tracer componenet as detailed in the paper (Section 5.2 and 5.2)
└─── analyzer               - Implements the Analyzer componenet as detailed in the paper (Section 4.4 and 5.3)
└─── executor               - Implements the Executor componenet as detailed in the paper (Section 4.5 and 5.4)
└─── schedule_parser        - Implementation of the parsing
└─── bug_reproductions      - Bugs reproduced by rose
└─── schedules              - Schedules which reproduce the bugs
└─── artifact_evaluation    - The artifact evaluation for EuroSys 26'
└─── auxiliary_scripts      - Auxiliary scripts to set up an environemnt where rose can run
└─── bpftool                - bpftool repository necessary for executor build
└─── vmlinux                - libbpf repository necessary for executor and tracer builds
└─── libbpf                 - libbpf repository necessary for executor build
└─── rw                     - Anduril repository
└─── tests                  - Auxiliary folders to save files
```
