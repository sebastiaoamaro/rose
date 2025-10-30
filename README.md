## Rose

### Auxiliary Scripts
Contains auxiliary scripts to setup Rose

### Bug Reproductions
Contains the base files to reproduce the bugs in the paper.

### Executor
Executes a schedule.

### Profiler
Profiles a specific execution of a system.

### Schedule Parser
Parses a schedule, constructs a fault_schedule.c file used by the executor.

### Schedules
Schedules created in the process of reproducing the bugs, also contains setup for redpanda, redisraft and mongodb.
Avoid having the scripts send output to stdout/stdin.

### Tests
Folder with tests for Rose and where schedules and traces during diagnosis are stored.

### Tracer
Tracer implementation.
