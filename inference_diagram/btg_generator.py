import pyAgrum as gum
import csv 
from model import *


pc = ProbCalculator([Node('a', 0.8), Node('b', 0.3)], 0)
combinations= pc.get_or()
for c in combinations:
    print("{} = {}".format(c.combination, c.prob))

p(pc.and_p())
p(pc.or_p())
c = Combinator(['a', 'b'])
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
        t = Threat.get_by_id(tids, v.tid_id)
        g.set_root_cpt(r.name, t.p)

    # for r in root_nodes:
    #     print(g.diag.cpt(r.name))

# setup_initial_cpt(g)
# gum_nodes = GumNode.generate_nodes(g.diag)
# current_nodes = g.get_root_nodes()
# current_nodes = [c.id for c in current_nodes]
# t = False

def btg_generate():
    if IS_SIMPLIFIED:
        vertices = Vertex.from_csv(simplified_folder(VERTICES_FILE))
        arcs = Arc.from_csv(simplified_folder(ARCS_FILE), vertices)
        tids = Threat.from_csv(folder_data(TID_FILE))
    else:
        vertices = Vertex.from_csv(complete_folder(VERTICES_FILE))
        arcs = Arc.from_csv(complete_folder(ARCS_FILE), vertices)
        tids = Threat.from_csv(folder_data(TID_FILE))

    g = GumUtils()
    g.generate_bayesian(vertices, arcs)
    setup_initial_cpt(g, vertices, tids)
    return g
    # leaf_nodes = g.get_leaf_nodes()
# while g.remaining_cpt() or t is True:
#     for current_node in current_nodes:
#         children = g.get_children(current_node)
#         for child in children:
#             parents = g.get_parents(child)
#             child = GumNode.find_by_id(gum_nodes, child)
#             v = Vertex.find_by_name(child.name)
#             if v.is_and():



#     t = True

#     current_nodes = children

# e()
    

# for l in leaf_nodes:
#     v = Vertex.find_by_name(vertices, l.name)

# # diag=gum.loadID("btg.bifxml")
# # g = GumUtils(diag)
# # nodes = g.get_leaf_nodes()
# # for n in nodes:
# #     print(n.get_cpt())













# # vertices = []
# # arcs = []
# # thidProb = {}
# # #dict containing p(v) of a node 
# # arcsDict = {}
# # #dict containing parents of a node 
# # invArcsDict = {}

# # vertices = []
# # arcs = []
# # thidProb = {}
# # #dict containing p(v) of a node 
# # arcsDict = {}
# # #dict containing parents of a node 
# # invArcsDict = {}



# # def init_data(folder_fn):
# #   # Get vertices nodes
# #   with open(folder_fn(VERTICES_FILE)) as csv_file:
# #     csv_reader = csv.reader(csv_file, delimiter=',')
# #     for row in csv_reader:
# #       v = Vertex(row[0], row[1], row[2], row[3])
# #       vertices.append(v)
      
# #   # arc nodes extraction 
# #   with open(folder_fn(ARCS_FILE)) as csv_file:
# #     csv_reader = csv.reader(csv_file, delimiter=',')
# #     for row in csv_reader:
# #       [int(i) for i in row]
# #       arcs.append(row)
# #       if row[0] in invArcsDict.keys():
# #         invArcsDict[row[0]].append(row[1])
# #       else:
# #         invArcsDict[row[0]] = []
# #         invArcsDict[row[0]].append(row[1])
# #       arcsDict[row[1]] = row[-1]

# #   #prelievo informazioni delle thid prob
# #   with open(folder_data(TID_FILE)) as csv_file:
# #     csv_reader = csv.reader(csv_file, delimiter=',')
# #     for row in csv_reader:
# #       thidProb[row[0]] = float(row[-1])

# # #init_data(complete_folder)
# # if IS_SIMPLIFIED:
# #   init_data(simplified_folder)
# # else:
# #   init_data(complete_folder)


# # def multiplyList(myList) :
# #     # Multiply elements one by one
# #     result = 1
# #     for x in myList:
# #          result = result * x
# #     return result



