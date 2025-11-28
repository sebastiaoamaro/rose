class Node:
    name = ""
    pid = 0
    pid_file = ""
    veth = ""
    ip = ""
    script = ""
    node_nr = 0
    env = ""
    container = 0
    container_type = 1
    binary = ""
    leader_symbol = ""
    leader = 0

    def to_yaml(self):
        return {
            self.name: {
                "name": self.name,
                "container": self.container == 1,
                "binary": self.binary,
                "leader_symbol": self.leader_symbol,
                "ip": self.ip,
                "leader": self.leader == 1,
                "script": self.script,
            }
        }


def parse_nodes(nodes):
    nodes_dict = {}
    node_nr = 0
    for key, value in nodes.items():
        nodes_dict[key] = createNode(key, value, node_nr)
        node_nr += 1

    return nodes_dict


def createNode(name, nodeconfig, node_nr):
    node = Node()

    node.name = name
    node.node_nr = node_nr

    keys = nodeconfig.keys()

    if "pid" in keys:
        node.pid = nodeconfig["pid"]

    if "veth" in keys:
        node.veth = nodeconfig["veth"]

    if "container" in keys:
        if nodeconfig["container"]:
            node.container = 1
        else:
            node.container = 0

    if "ip" in keys:
        node.ip = nodeconfig["ip"]

    if "script" in keys:
        node.script = nodeconfig["script"]

    if "env" in keys:
        node.env = nodeconfig["env"]

    if "binary" in keys:
        node.binary = nodeconfig["binary"]

    if "leader_symbol" in keys:
        node.leader_symbol = nodeconfig["leader_symbol"]

    if "leader" in keys:
        if nodeconfig["leader"]:
            node.leader = 1

    if "container_type" in keys:
        if nodeconfig["container_type"] == "docker":
            node.container_type = 1
        if nodeconfig["container_type"] == "lxc":
            node.container_type = 2
        # If the compose starts the process itself
        if nodeconfig["container_type"] == "docker_automatic":
            node.container_type = 3

    if "pid_file" in keys:
        node.pid_file = nodeconfig["pid_file"]

    return node


def build_nodes_cfile(file, nodes):
    build_nodes_begin = """\nnode* build_nodes(){\n"""
    file.write(build_nodes_begin)

    build_nodes_malloc = (
        """    node* nodes = ( node*)malloc(NODE_COUNT * sizeof(node));\n"""
    )
    build_nodes_malloc = build_nodes_malloc.replace("#size", str(len(nodes.items())))
    file.write(build_nodes_malloc)

    node_nr = 0
    for name, node in nodes.items():
        build_node = """    create_node(&nodes[#nodenr],"#name",#pid,"#pid_file","#veth","#ip","#script","#env",#container,#container_type,"#binary","#leader_symbol",#leader);\n"""
        build_node = build_node.replace("#nodenr", str(node_nr))
        build_node = build_node.replace("#name", node.name)
        build_node = build_node.replace("#veth", node.veth)
        build_node = build_node.replace("#ip", node.ip)
        build_node = build_node.replace("#script", node.script)
        build_node = build_node.replace("#pid_file", node.pid_file)
        build_node = build_node.replace("#pid", str(node.pid))
        build_node = build_node.replace("#env", str(node.env))
        build_node = build_node.replace("#container_type", str(node.container_type))
        build_node = build_node.replace("#container", str(node.container))
        build_node = build_node.replace("#binary", str(node.binary))
        build_node = build_node.replace("#leader_symbol", str(node.leader_symbol))
        build_node = build_node.replace("#leader", str(node.leader))

        file.write(build_node)
        node_nr += 1

    build_nodes_end = """
    return nodes;
}"""
    file.write(build_nodes_end)
