import json
import os
import shutil
from pyvis.network import Network

# CONSTANTS

cwd = os.getcwd()
json_file_path = cwd + "/../target/rules.json"
graph_file_name = "./java_graph.html"
graph_height = "960px"
# Can add buttons to play with the following things: ['nodes', 'edges', 'physics']
graph_buttons = ['physics']
color_entry_points = '#eb4034'
color_depending_rules = '#97c2fc'
color_parameter_types = '#32a852'

# GLOBAL VARIABLES

# Map taking a node ID and returning another map taking a matcher ID and returning a matcher object
nodes_map = {}

# Map taking a node ID and returning a boolean indicating whether the node is an entry point
entry_points_map = {}

# Set of edges (tuple of two node IDs)
edges_set = set()

# Set of parameter types (usually interfaces)
parameters_set = set()


# HELPER FUNCTIONS

# Returns the first `invokedObjectType` from a matcher ID
def get_node_id_from_matcher_id(mid):
    return mid.split(' ')[0]


# Get a detailed text describing a graph node
# It appears when hovering on one node
def get_node_details(nid, is_an_entry_point):
    matchers = nodes_map[nid].values()
    string_details = "[DEPENDING RULE]\n"
    if is_an_entry_point:
        string_details = "[ENTRY-POINT]\n"
    for i, matcher in enumerate(matchers):
        if i == 0:
            # Write the type of the node
            types = matcher["invokedObjectTypeStrings"]
            if len(types) > 0:
                for j, type in enumerate(types):
                    string_details += f"Type: {type}"
                    if j < len(types) - 1:
                        string_details += ", "
                string_details += "\n"
            else:
                string_details += "Type: Unknown\n"

        # Write a list of method names with their parameters
        names = matcher["methodNames"]
        if len(names) > 0:
            for j, name in enumerate(names):
                string_details += f" • {name}"
                if j < len(names) - 1:
                    string_details += ", "

        string_details += "("
        params = matcher["parameterTypes"]
        if len(params) > 0:
            for j, param in enumerate(params):
                string_details += f"{param}"
                if j < len(params) - 1:
                    string_details += ", "
        string_details += ")\n"
    return string_details


# PARSING THE DATA

# Loading JSON file
print("\rloading...", end='')
f = open(json_file_path)
data = json.load(f)
entry_points_len = len(data)

# `all_rules` is a queue of rules to process
all_rules = data

for i in range(len(all_rules)):
    rule = all_rules[i]

    matcher_id = rule["id"]
    node_id = get_node_id_from_matcher_id(matcher_id)

    if nodes_map.get(node_id) is None:
        # First occurrence of the node: initialize its map of matcher IDs
        nodes_map[node_id] = {}
        nodes_map[node_id][matcher_id] = rule["methodMatcher"]
    else:
        nodes_map[node_id][matcher_id] = rule["methodMatcher"]

    entry_points_map[node_id] = rule["isEntryPoint"]

    for mapping in rule["parameterNextDetectionRules"]:
        parameter = mapping["key"] + " [P]"
        subrules = mapping["values"]

        if len(subrules) > 0:
            parameters_set.add(parameter)
            edges_set.add((node_id, parameter))
            for subrule in subrules:
                edges_set.add((parameter, get_node_id_from_matcher_id(subrule)))

    for subrule in rule["nextDetectionRules"]:
        edges_set.add((node_id, get_node_id_from_matcher_id(subrule)))

# Closing JSON file
f.close()

# Recap of the processing
print(
    f"\r{len(all_rules)} rules analyzed, {len(nodes_map.keys())} nodes, {len(edges_set)} edges, {len(parameters_set)} parameters")

# BUILDING THE GRAPH

# Create a Network object
net = Network(height=graph_height, directed=True, filter_menu=True, notebook=False)

node_ids = list(nodes_map.keys())
# Iterate on each node to add it to the graph
for i in range(len(node_ids)):
    node_id = node_ids[i]

    # Coloring depending on if the node is an entry point or not
    color = color_depending_rules
    is_entry_point = entry_points_map[node_id]
    if is_entry_point:
        color = color_entry_points

    net.add_node(node_id, label=node_id, title=get_node_details(node_id, is_entry_point), color=color)

# Iterate on each parameter to add it to the graph with a different color
for param_type in parameters_set:
    net.add_node(param_type, label=param_type[:-4], color=color_parameter_types,
                 title=f"[PARAMETER TYPE/INTERFACE]\nType: {param_type[:-4]}")

# Add all the edges between the nodes
for edge in edges_set:
    net.add_edge(edge[0], edge[1])

# Visualize the graph and export the HTML file
net.force_atlas_2based()
net.show_buttons(filter_=graph_buttons)
net.save_graph(graph_file_name)


indexFile = "./index.html"
if os.path.exists(indexFile):
    os.remove(indexFile)

shutil.move(graph_file_name, indexFile)
