class ExecutionPlan:
    setup = None
    workload = None
    cleanup = None
class Setup:
    script = ""
    duration = 0
class Workload:
    script = ""
    wait_time = 0
class Cleanup:
    script = ""
    duration = 0

def parse_execution_plan(plan):
    exe_plan = ExecutionPlan()

    if "setup" in plan:
        setup = Setup()

        setup.script = plan['setup']['script']
        setup.duration = int(plan['setup']['duration'])

        exe_plan.setup = setup

    if "workload" in plan:
        workload = Workload()

        workload.script = plan['workload']['script']

        wait_time = 0;
        if "wait_time" in plan['workload']:
            wait_time = int(plan['workload']['wait_time'])

        exe_plan.workload = workload
        exe_plan.wait_time = wait_time

    if "cleanup" in plan:
        cleanup = Cleanup()

        cleanup.script = plan['cleanup']['script']
        cleanup.duration = int(plan['cleanup']['duration']) 

        exe_plan.cleanup = cleanup

    return exe_plan

def build_plan_cfile(file,plan):
    exe_plan_begin = """\nexecution_plan* build_execution_plan(){\n"""
    file.write(exe_plan_begin)

    exe_plan_malloc = """    execution_plan* exe_plan = ( execution_plan*)malloc(1 * sizeof(execution_plan));\n"""
    file.write(exe_plan_malloc)

    exe_plan_setup = """    create_execution_plan(exe_plan,"#setup_script",#setup_duration,"#workload_script","#cleanup_script",#cleanup_sleep_time);"""


    if not plan.setup is None:
        exe_plan_setup =  exe_plan_setup.replace("#setup_duration",str(plan.setup.duration))
        exe_plan_setup = exe_plan_setup.replace("#setup_script",plan.setup.script)
    else:
        exe_plan_setup = exe_plan_setup.replace("#setup_duration",str(0))
        exe_plan_setup = exe_plan_setup.replace("#setup_script","")

    if not plan.workload is None:
        exe_plan_setup = exe_plan_setup.replace("#workload_script",plan.workload.script)
    else:
        exe_plan_setup = exe_plan_setup.replace("#workload_script","")

    if not plan.cleanup is None:
        exe_plan_setup =  exe_plan_setup.replace("#cleanup_sleep_time",str(plan.cleanup.duration))
        exe_plan_setup = exe_plan_setup.replace("#cleanup_script",plan.cleanup.script)
    else:
        exe_plan_setup =  exe_plan_setup.replace("#cleanup_sleep_time",str(0))
        exe_plan_setup = exe_plan_setup.replace("#cleanup_script","")

    file.write(exe_plan_setup)
    exe_plan_end= """
    return exe_plan;
}"""

    file.write(exe_plan_end)

def build_empty_plan_cfile(file):
    exe_plan_begin = """\nexecution_plan* build_execution_plan(){\n"""
    file.write(exe_plan_begin)
    exe_plan_end= """
    return NULL;
}"""
    file.write(exe_plan_end)
