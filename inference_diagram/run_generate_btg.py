# import pyAgrum.lib.notebook as gnb
from model import *
from btg_generator import *



if __name__ == "__main__":
    gu = GumUtils()
    gu = btg_generate()

    def cpt(gu, names):
        for var_name in names: 
            if not gu.has_parents(var_name):
                p("root node skip {}".format(var_name))
            # print(gu.diag.cpt(var_name))
            else:
                # print("{} has parents".format(var_name))
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
    # print(leaf_nodes[0])
    print(leaf_nodes[0])
    for l in leaf_nodes:
        cpt(gu, [l])
    gum.saveBN(gu.diag, "filled_btg.bifxml")
    print("btg filled saved")
        # cpt(gu, l)
    # gnb.showBN(gu.diag)