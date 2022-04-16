import csv
import pyAgrum as gum
import re
import itertools
from model import *
from btg_generator import *
import re

gu = GumUtils()
gu = btg_generate()

def cpt(gu, names):
    for var_name in names: 
        if not gu.has_parents(var_name):
            dbg("root node skip {}".format(var_name))
        else:
            parents = gu.get_parents_names(var_name)
            gum_node = gu.get_gum_node(var_name)
            cpt(gu, parents)
            if gum_node.is_and:
                and_probabilities = gu.generate_and_cpt(var_name)
                gu.set_cpt(var_name, and_probabilities)
            elif gum_node.is_or:
                or_probabilities = gu.generate_or_cpt(var_name)
                gu.set_cpt(var_name, or_probabilities)



leaf_nodes = GumNode.get_names(gu.get_goal_nodes())
for l in leaf_nodes:
    cpt(gu, [l])

goal_nodes = gu.get_goal_nodes()

dbg("Make inference")
ie=gum.LazyPropagation(gu.diag)
ie.makeInference()
for l in goal_nodes:
    print(ie.posterior(l.name))
# print (ie.posterior("w"))
