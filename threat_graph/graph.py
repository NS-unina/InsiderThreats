import sys
import itertools

def usage():
    print("[-] python graph.py <threat graph folder>")
    sys.exit(-1)

def elimination_width(graph):
    max_neighbors = 0
    for i in sorted(set(itertools.chain.from_iterable(graph))):
        neighbors = set([a for (a, b) in graph if b == i] + [b for (a, b) in graph if a == i])
        max_neighbors = max(len(neighbors), max_neighbors)
        graph = [edge for edge in graph if i not in edge] + [(a, b) for a in neighbors for b in neighbors if a < b]
    return max_neighbors

def get_no_vertices(vertices_file):
    with open(vertices_file, 'r') as f:
        return len(f.readlines())


def get_no_arcs(arcs_file):
    with open(arcs_file, 'r') as f:
        return len(f.readlines())
    

def treewidth(graph):
    vertices = list(set(itertools.chain.from_iterable(graph)))
    min_width = len(vertices)
    for permutation in itertools.permutations(vertices):
        new_graph = [(permutation[vertices.index(a)], permutation[vertices.index(b)]) for (a, b) in graph]
        min_width = min(elimination_width(new_graph), min_width)
    return min_width



def get_tuple(entry):
    entry = entry.replace("\n", "")
    splitted = entry.split(",")
    first = splitted[0]
    second = splitted[1]
    return (first, second)

def generate_graph(arcs_file):
    arr = []
    with open(arcs_file, 'r') as f:
        lines = f.readlines()
        for l in lines: 
            tuple = get_tuple(l)
            arr.append(tuple)
    return arr

def get_header(no_vertices, no_arcs):
    return "p tw {} {}".format(no_vertices, no_arcs)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    arcs_file = "{}/ARCS.csv".format(sys.argv[1])
    vertices_file = "{}/VERTICES.csv".format(sys.argv[1])
    no_arcs = get_no_arcs(arcs_file)
    no_vertices = get_no_vertices(vertices_file)


    header = get_header(no_vertices, no_arcs)
    body = ""
    graph = generate_graph(arcs_file)
    for t in graph:
        body = body + "{} {}\n".format(t[0], t[1])
    
    print(header)
    print(body)


    






    # graph = generate_graph(arcs_file)
    # print("Nodes, Arcs, Treewidth")
    # print("{}, {}, {}".format(no_vertices(vertices_file), no_arcs(arcs_file), treewidth(graph)))
    