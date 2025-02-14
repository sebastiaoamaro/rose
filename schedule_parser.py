import yaml
import sys
from parser.faults import parse_faults, build_faults_cfile
from parser.nodes import parse_nodes, build_nodes_cfile
from parser.aux import calculate_fault_count
from parser.execution_plan import parse_execution_plan,build_plan_cfile,build_empty_plan_cfile
from parser.tracer import parse_tracer,build_tracer_cfile,build_empty_tracer_cfile

def parse_fault_schedule(filename):
    file = open(filename,"r")

    fault_schedule = yaml.safe_load(file)

    plan = None
    tracer = None
    faults = None
    max_time = 60
    if 'execution_plan' in fault_schedule:
        plan = parse_execution_plan(fault_schedule['execution_plan'])

        if 'tracer' in fault_schedule['execution_plan']:
            tracer = parse_tracer(fault_schedule['execution_plan']['tracer'])

        if 'maximum_time' in fault_schedule['execution_plan']:
            max_time = fault_schedule['execution_plan']['maximum_time']

    nodes = parse_nodes(fault_schedule['nodes'])

    if 'faults' in fault_schedule:
        faults = parse_faults(fault_schedule['faults'],nodes)
    
    build_cfile(nodes,faults,plan,tracer,max_time)


def build_cfile(nodes,faults,plan,tracer,max_time):

    file = open('faultschedule.c','w+')

    file_template = open('parser/faultschedule_template.c').read()
    file_template = file_template.replace("#node_count",str(len(nodes.items())))

    fault_count = 0
    if faults is not None:
        fault_count = calculate_fault_count(faults)
    file_template = file_template.replace("#fault_count",str(fault_count))

    file_template = file_template.replace("#maximum_time",str(max_time))

    file.write(file_template)
    
    if not plan is None:
        build_plan_cfile(file,plan)
    else:
        build_empty_plan_cfile(file)

    if not tracer is None:
        build_tracer_cfile(file,tracer)
    else:
        build_empty_tracer_cfile(file)

    build_nodes_cfile(file,nodes)
    build_faults_cfile(file,nodes,faults)

    return 0


def main():
    filename = sys.argv[1]

    parse_fault_schedule(filename)

if __name__ == "__main__":
    main()