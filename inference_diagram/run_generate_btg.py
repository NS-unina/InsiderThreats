# import pyAgrum.lib.notebook as gnb
from model import *
from risk import *
from btg_generator import *
from operator import attrgetter
import argparse
import csv

output = True

def ps():
    print("\n=============================\n")


security_controls  = SecurityControl.from_json(folder_data('json_sc.json'))
scm = SecurityControlManager(security_controls)
assets = AssetImpact.from_csv()
performance_list = []

def cpt(gu, names):
    for var_name in names: 
        if not gu.has_parents(var_name):
            pr("root node skip {}".format(var_name))
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


def get_prob(ie, name):
    return ie.posterior(name)[1]

class PerformanceCombination:
    """
        This class contains the list of combinations with relative performance costs
    """
    def __init__(self, no_combination, performance, risk, cost):
        self.no_combination  = no_combination
        self.performance = performance
        self.risk = risk
        self.cost = cost
    def best_performance(performance_list):
        best = max(performance_list, key=attrgetter('performance'))
        return best
    def minimal_risk(performance_list):
        min_risk = min(performance_list, key=attrgetter('risk'))
        return min_risk




def run_combination(no_combination):
    subset = scm.get_subset(no_combination)
    implementation_cost = scm.get_implementation_cost(subset)   
    pr("No of implemented security controls: {}".format(len(subset)))

    """ 
        Generate the bayesian threat graph, 
        this involves three steps: 
        1. Generate the reduced threat graph
        2. Generate the bayesian threat graph 
        3. Setup the cpt
    """
    gu = btg_generate(subset)



    # Setup the cpt of all nodes through the AND and OR noisy generation algorithm
    leaf_nodes = GumNode.get_names(gu.get_goal_nodes())
    for l in leaf_nodes:
        cpt(gu, [l])

    # Now we can do the inference
    pr("Make inference")
    ie=gum.LazyPropagation(gu.diag)
    ie.makeInference()
    gum_nodes = gu.get_goal_nodes()
    ps()
    pr("Reduced probabilities:") 
    for g in gum_nodes:
        pr("{} = {}".format(g.name, get_prob(ie, g.name)))
    ps()


    threat_risks = []
    for g in gum_nodes:
        impact = AssetImpact.get_from_goal(assets, g.name)
        loss = impact.get_security_incident_loss()
        prob = get_prob(ie, g.name)
        threat_risks.append(Risk(prob, loss))
        # p("Loss for {} against {} = {}".format(g.name, impact.asset, impact.get_security_incident_loss()))

    total_risk = Risk.total(threat_risks)
    performance_value = -1
    # Only consider implementation costs
    if implementation_cost != 0:
        performance_value = total_risk / implementation_cost
    performance_obj = PerformanceCombination(no_combination, performance_value, total_risk, implementation_cost)
    
    ps()
    pr("Implementation cost: {}".format(implementation_cost))
    pr("Total risk: {}".format(total_risk))
    pr("Performance val: {}".format(performance_value))
    ps()

    return performance_obj
    performance_list.append(performance_obj)

    
if __name__ == "__main__":
    #parser = argparse.ArgumentParser(description='Chose optimium SC')
    
    gu = GumUtils()
    
    # Initialize the security control
    no_combinations = scm.get_no_combinations()

    pr("No security control combinations: {}".format(no_combinations))
    
    with open('result.csv', mode='w') as file:
        for i in range(0, no_combinations):
            performace_result = run_combination(i)
            performance_writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            performance_writer.writerow([performace_result.no_combination, performace_result.performance, performace_result.risk, performace_result.cost])
            performance_list.append(performace_result)
        
    best_perf = PerformanceCombination.best_performance(performance_list)
    min_risk  = PerformanceCombination.minimal_risk(performance_list)
    pr("The best performance ({}) is given by combination {}".format(best_perf.performance, best_perf.no_combination))
    pr("The minimal risk ({}) is given by combination {}".format(min_risk.risk, min_risk.no_combination))


    # gum.saveBN(gu.diag, "filled_btg.bifxml")
    # print("btg filled saved")