import pyAgrum as gum
import csv 
from model import *


# pc = ProbCalculator([Node('a', 0.8), Node('b', 0.3)], 0)
# combinations= pc.get_or()
# for c in combinations:
#     print("{} = {}".format(c.combination, c.prob))

# p(pc.and_p())
# p(pc.or_p())
# c = Combinator(['a', 'b'])
# print(c.combinations[0])
# p(Combinator.is_all_one(c.combinations[3]))
# p(Combinator.is_all_zeros(c.combinations[1]))
# p(Combinator.is_all_zeros(c.combinations[0]))
# p(Combinator.is_all_zeros(c.combinations[3]))
# print(c.combinations[1].values())





def setup_initial_cpt(g, vertices, tids):
    root_nodes = g.get_root_nodes()
    for r in root_nodes:
        v = Vertex.find_by_name(vertices, r.name)
        # NOT REQUIRED AS ALL ROOTS ARE TIDS
        # if v.is_tid():
        if Threat.is_vector_threat(tids, v.text):
            t = Threat.get_vector_threat(tids, v.text)
        else: 
            # For ransomware and data exfiltration
            t = Threat.get_by_id(tids, v.tid_id)
        g.set_root_cpt(r.name, t.p)

    # for r in root_nodes:
    #     print(g.diag.cpt(r.name))

# setup_initial_cpt(g)
# gum_nodes = GumNode.generate_nodes(g.diag)
# current_nodes = g.get_root_nodes()
# current_nodes = [c.id for c in current_nodes]
# t = False

def create_or_vertex(goal):
    return Vertex(-1, "OR for {}".format(goal.text), "OR", -1)

def add_no_duplicate(vertices, v):
    for vert in vertices: 
        if v.text == vert.text:
            return vertices
    vertices.append(v)
    return vertices

def reduce_graph(vertices, arcs):
    # Only rules vertices are needed
    # rules_vertices = [v for v in vertices if v.is_and()]
    # no_goals_vertices = [r for r in rules_vertices if not r.is_threat_goal()]

    reduced_vertices = []
    reduced_arcs = []
    threat_goals = [r for r in vertices if r.is_final_node()]
    for g in threat_goals: 
        # Add goal to reduced vertices
        reduced_vertices = add_no_duplicate(reduced_vertices, g)
        goal_parents = Arc.get_parents(arcs, g)
        vector_threats = []
        fp = goal_parents[0]
        tid = Arc.get_parent_tid(arcs, fp)
        reduced_vertices = add_no_duplicate(reduced_vertices, tid)
        
        or_node = create_or_vertex(g)
        reduced_vertices = add_no_duplicate(reduced_vertices, or_node)
        for gp in goal_parents:
            # Attach all vector threats and tid to or node
            vector_threat = Arc.get_parent_no_tid(arcs, gp)
            print("GOAL {}".format(g.text))
            print("Vector threat {}".format(vector_threat.text))
            vector_threats.append(vector_threat)
            # Add or node and vector_threat to node
            reduced_vertices = add_no_duplicate(reduced_vertices, vector_threat)
            reduced_arcs.append(Arc(vector_threat, or_node))
            
            # vector_threats -> OR_NODE -> Goal
            # for vt in vector_threats:
        # OR_NODE AND tid -> Goal
        reduced_arcs.append(Arc(or_node, g))
        reduced_arcs.append(Arc(tid, g))
    return reduced_vertices, reduced_arcs

        

            

    for r in no_goals_vertices:
        print("ID {} ".format(r.id))
        # Set no goals vertices to vertices
        dest = Arc.get_dest(arcs, r)
        dest = Arc.get_dest(arcs, dest)
        goal = Arc.get_dest(arcs, dest)
        parents = Arc.get_parents(arcs, goal)
        print("Goal: {}".format(goal.text))
        print("NO PARENTS: {}".format(len(parents)))
        # Arc.set_dest(arcs, r, goal)

    rule_arcs = Arc.get_rules_arcs(rules_vertices, arcs)
    for t in threat_goals:
        rules_vertices.append(t)
    for r in rule_arcs:
        print("{} -> {}".format(r.src.text, r.dest.text))
    return rules_vertices , rule_arcs

def btg_generate():
    if IS_SIMPLIFIED:
        vertices = Vertex.from_csv(simplified_folder(VERTICES_FILE))
        arcs = Arc.from_csv(simplified_folder(ARCS_FILE), vertices)
        tids = Threat.from_csv(folder_data(TID_FILE))
    else:
        vertices = Vertex.from_csv(complete_folder(VERTICES_FILE))
        arcs = Arc.from_csv(complete_folder(ARCS_FILE), vertices)
        tids = Threat.from_csv(folder_data(TID_FILE))
    rules_vertices, rules_arcs = reduce_graph(vertices, arcs) 
    g = GumUtils()
    g.generate_bayesian(rules_vertices, rules_arcs)
    setup_initial_cpt(g, rules_vertices, tids)
    return g
