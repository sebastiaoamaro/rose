#Examples of how to use the schedule generator

Generate schedules with varying call counts in a condition, inputs are: base_schedule, mode, call_count_max, fault_name and condition_name

  python3 schedulegenerator.py reproducedbugs/zookeeper/bug_2247_reproduced.yaml call_count write_fail condition1 12 generatedschedules/