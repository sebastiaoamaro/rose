class ExecutionPlan:
    setup = None
    workload = None
class Setup:
    script = ""
    duration = 0
class Workload:
    script = ""

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

        exe_plan.workload = workload

    return exe_plan

def build_plan_cfile(file,plan):
    exe_plan_begin = """\nexecution_plan* build_execution_plan(){\n"""
    file.write(exe_plan_begin)

    exe_plan_malloc = """    execution_plan* exe_plan = ( execution_plan*)malloc(1 * sizeof(execution_plan));\n"""
    file.write(exe_plan_malloc)

    exe_plan_setup = """    create_execution_plan(exe_plan,"#setup_script",#setup_duration,"#workload_script");"""


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
