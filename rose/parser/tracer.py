class Tracer:
    tracer_location = ""
    pipe_location = ""
    functions_file = ""
    binary_path = ""

def parse_tracer(tracer_yaml):
    tracer = Tracer()

    tracer.tracer_location = tracer_yaml['tracer_location']

    tracer.pipe_location = tracer_yaml['pipe_location']

    tracer.functions_file = tracer_yaml['functions_file']

    tracer.binary_path = tracer_yaml['binary_to_examine']


    return tracer

def build_tracer_cfile(file,tracer):
    
    tracer_begin = """\n tracer* build_tracer(){\n"""
    file.write(tracer_begin)

    tracer_malloc = """    tracer* deployment_tracer = (tracer*)malloc(1 * sizeof(tracer));\n"""
    file.write(tracer_malloc)

    tracer_setup = """    create_tracer(deployment_tracer,"#tracer_location","#pipe_location","#functions_file","#binary_path");"""

    tracer_setup = tracer_setup.replace("#tracer_location",tracer.tracer_location)
    tracer_setup = tracer_setup.replace("#pipe_location",tracer.pipe_location)
    tracer_setup = tracer_setup.replace("#functions_file",tracer.functions_file)
    tracer_setup = tracer_setup.replace("#binary_path",tracer.binary_path)


    file.write(tracer_setup)
    tracer_end= """
    return deployment_tracer;
}"""

    file.write(tracer_end)

def build_empty_tracer_cfile(file):
    tracer_begin = """\n tracer* build_tracer(){\n"""
    file.write(tracer_begin)
    tracer_end= """
    return NULL;
}"""
    file.write(tracer_end)