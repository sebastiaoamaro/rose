import yaml
import sys
from faults import parse_faults, build_faults_cfile
from nodes import parse_nodes, build_nodes_cfile
from aux import calculate_fault_count
from execution_plan import parse_execution_plan,build_plan_cfile,build_empty_plan_cfile

def parse_fault_schedule(filename):
    file = open(filename,"r")

    fault_schedule = yaml.safe_load(file)

    plan = None
    if 'execution_plan' in fault_schedule:
        plan = parse_execution_plan(fault_schedule['execution_plan'])

    nodes = parse_nodes(fault_schedule['nodes'])

    faults = parse_faults(fault_schedule['faults'],nodes)

    build_cfile(nodes,faults,plan)


def build_cfile(nodes,faults,plan):

    file = open('faultschedule.c','w+')

    file_template = open('faultschedule_template.c').read()
    file_template = file_template.replace("#node_count",str(len(nodes.items())))

    fault_count = calculate_fault_count(faults)
    file_template = file_template.replace("#fault_count",str(fault_count))

    file.write(file_template)
    
    if not plan is None:
        build_plan_cfile(file,plan)
    else:
        build_empty_plan_cfile(file)

    build_nodes_cfile(file,nodes)
    build_faults_cfile(file,nodes,faults)
    return 0


def main():
    filename = sys.argv[1]

    parse_fault_schedule(filename)

if __name__ == "__main__":
    main()