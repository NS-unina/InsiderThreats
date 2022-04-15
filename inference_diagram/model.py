import re
import csv
from os import path
import pyAgrum as gum
import sys
from functools import reduce
from itertools import product

VERTICES_FILE = "VERTICES.CSV"
ARCS_FILE = "ARCS.CSV"
TID_FILE = "thid.csv"
SC_ASSOCIATION_FILE = "scAssociation.csv"
IS_SIMPLIFIED = False
TEST_BENEFIT_SC = 0
TEST_THREAT_IMPACT     = 100000
DEBUG = True

def p(s):
    if DEBUG:
        print("[+] {}".format(s))

def e():
    sys.exit(-1)


## Folders that change depending on the threat model
def complete_folder(f):
  return path.join("complete", f)

def simplified_folder(f):
  return path.join("simplified", f)

# Data folder, with probabilities and other stuff
def folder_data(f):
  return path.join("data", f)

class ProbVal:
  def __init__(self, p_true):
    self.p_true = p_true
    self.p_false = 1 - p_true

class Node:
    def __init__(self, name, prob_true):
      """Accept a node name and its true probability
      Args:
          name (str): The node name
          prob_true (prob): a true probability
      """
      self.name = name
      self.prob_true = prob_true

        
class ProbCombination:
    def __init__(self, combination, p):
        self.combination = combination
        self.prob = p

    def __str__(self):
        return "{} = {}".format(self.combination, self.prob)

class ProbCalculator:
    """
      Accept a list of prob nodes and generate the and and or 
    """
    def __init__(self, nodes, is_and = 1):
        self.nodes = nodes
        self.no_parents = len(nodes)
        self.is_and = is_and

    def and_p(self):
        # and(p)
        mul = lambda x, y: x * y
        probs = [n.prob_true for n in self.nodes]
        return reduce(mul, probs)

    def or_p(self):
        # 1 - and(1 - p)
        mul = lambda x, y: x * y
        or_probs = [1 - n.prob_true for n in self.nodes]
        return 1 - reduce(mul, or_probs)

    def get_and(self):
        # ALL COMBINATIONS TO 0 EXCEPT ALL ONES THAT HAS AND PROB
        comb = Combinator([n.name for n in self.nodes])
        and_probabilities = []
        for c in comb.combinations:
            a = ProbCombination(c, ProbVal(0))
            if Combinator.is_all_one(c):
                a.prob = ProbVal(self.and_p())
            and_probabilities.append(a)
        return and_probabilities
        
    def get_or(self):
        # ALL COMBINATIONS TO 0 EXCEPT ALL ONES THAT HAS AND PROB
        comb = Combinator([n.name for n in self.nodes])
        or_probabilities = []
        for c in comb.combinations:
            a = ProbCombination(c, ProbVal(0))
            if Combinator.is_all_zeros(c):
                a.prob = ProbVal(0)
            else: 
                a.prob = ProbVal(self.or_p())
            or_probabilities.append(a)
        return or_probabilities

class Combinator:
    def __init__(self, names):
        # if len(names) == 2, then : [(0, 0), (0, 1), (1, 0), (1, 1)]
        combinations = list(product([0, 1], repeat = len(names))) 
        generated_combinations = []
        for c in combinations:
            generated = dictionary = dict(zip(names, c))
            generated_combinations.append(generated)
        self.names = names 
        self.combinations = generated_combinations

    def is_all_one(combination):
        all_ones = [c == 1 for c in combination.values()]
        return all(all_ones)

    def is_all_zeros(combination):
        all_zeros = [c == 0 for c in combination.values()]
        return all(all_zeros)

    def get_all_one_combination(combinations):
        for c in combinations:
            if Combinator.is_all_one(c):
                return c
        return None




class GumNode:
    # A bayesian threat node
    def __init__(self, diag, id, name, is_and, is_or):
        """A Gum node

        Args:
            diag (PyAgrum Bayesian network): A bayesian network
            id (int): An identifier in bayesian network
            name (str): The node name
            type (str): OR, AND, or LEAF
        """
        self.diag = diag
        # The id in the pyAgrum structure
        self.id = id
        # The name in the pyAgrum structure
        self.name = name
        self.is_leaf = self.is_leaf_node(id)
        self.is_root = self.is_root_node(id)
        self.is_and = is_and
        self.is_or = is_or

    def is_leaf_node(self, id):
        return len(self.diag.children(id)) == 0

    def is_root_node(self, id):
        return len(self.diag.parents(id)) == 0

    def get_cpt(self):
        return self.diag.cpt(self.id)
    
    def generate_nodes(diag, vertices):
        """Generate nodes from pyagrum diag
        Takes diag names, for each name extract the id and append to GumNode structure

        Args:
            diag (PyAgrum Bayesian network): A bayesian network
            vertices (list(Vertex)): A list of vertex

        Returns:
            gum nodes: A list of gum nodes
        """
        names = diag.names()
        gum_nodes = []
        for n in names: 
            the_id = diag.idFromName(n)
            v = Vertex.find_by_name(vertices, n)
            # print(v)
            gum_nodes.append(GumNode(diag, the_id, n, v.is_and(), v.is_or()))
        return gum_nodes

    def get_names(nodes):
        return [ n.name for n in nodes ]

    def find_by_name(gum_nodes, name):
        for g in gum_nodes:
            if g.name == name: 
                return g
        return None


    def find_by_id(gum_nodes, id):
        for g in gum_nodes:
            if g.id == id: 
                return g
        return None


            


class GumUtils:
    def __init__(self, diag = None):
        self.cpt_setted = []
        self.no_nodes = 0
        self.no_arcs = 0
        self.nodes = []
        if diag is None: 
            self.diag = gum.BayesNet('BayesianThreatGraph')
        else:
            self.diag = diag
        # self.nodes = GumNode.generate_nodes(self.diag)

    """
        Returns true until the no of set cpts is equal to number of nodes 
    """
    def remaining_cpt(self):
        return len(self.cpt_setted) < self.no_nodes 

    def has_parents(self, id):
        return len(self.diag.parents(id)) != 0

    def has_children(self, id):
        return len(self.diag.children(id)) != 0

    def get_root_nodes(self):
        return [n for n in self.nodes if n.is_root]

    def get_leaf_nodes(self):
        """ Returns a list of GUM Nodes

        Returns:
            list[GumNodes]: A list of gum nodes
        """
        return [n for n in self.nodes if n.is_leaf]

    def get_parents(self, name):
        parents = self.diag.parents(name)
        return [n for n in self.nodes if n.id in parents]

    def get_gum_node(self, name):
        return GumNode.find_by_name(self.nodes, name)

    def get_children(self, id):
        return self.diag.children(id)

    def generate_bayesian(self, vertices, arcs):
        p("Set vertices")
        for v in vertices:
            self.diag.add(gum.LabelizedVariable(v.get_name(), v.text, 2))
            self.no_nodes = self.no_nodes + 1
        p("Set arcs")
        for a in arcs:
            self.diag.addArc(a.src.get_name(), a.dest.get_name())
            self.no_arcs = self.no_arcs + 1
        self.nodes = GumNode.generate_nodes(self.diag, vertices)

    def generate_and_cpt(self, variable_name):
        """Generate and cpt
         - If a variable is 0, then the probability is 0
         - If all variables are 1, then the probability is given by and(parents)

        Args:
            variable_name (str): the variable name

        Returns:
            ProbCalculator: A list of "Combinator objects", namely, objects that allows the and / or noisy operation.
        """
        p("Generate \"AND\" cpt for {} node".format(variable_name))
        names = self.get_parents_names(variable_name)
        nodes = []
        for n in names:
            true_val = self.get_true_val(n)
            node = Node(n, true_val)
            nodes.append(node)
        prob_calculator = ProbCalculator(nodes)
        and_probabilities = prob_calculator.get_and()
        return and_probabilities

    def generate_or_cpt(self, variable_name):
        """Generate or cpt
         - If all variable are 0, then the probability is 0
         - Otherwise, the probability is given by 1 - and(1 - p_i), where p_i is the parent probability

        Args:
            variable_name (str): the variable name

        Returns:
            ProbCalculator: A list of "Combinator objects", namely, objects that allows the and / or noisy operation.
        """
        p("Generate \"OR\" cpt for {} node".format(variable_name))
        names = self.get_parents_names(variable_name)
        nodes = []
        for n in names:
            true_val = self.get_true_val(n)
            node = Node(n, true_val)
            nodes.append(node)
        prob_calculator = ProbCalculator(nodes)
        or_probabilities = prob_calculator.get_or()
        return or_probabilities


    def set_cpt(self, node_name, cpts):
        """ set cpt into a node
        Args:
            node_name (str): The node string
            cpts (array of Node objects): An array of nodes (tuples containing combinator and prob)
        """
        for c in cpts:
            self.diag.cpt(node_name)[c.combination] = [c.prob.p_false, c.prob.p_true]

    def set_root_cpt(self, node_name, prob):
        # Set cpt only if not already setted
        if node_name not in self.cpt_setted:
            self.diag.cpt(node_name).fillWith([1 - prob, prob])
            p("{} cpt configured".format(node_name))
            self.cpt_setted.append(node_name)
        else:
            p("{} already set!".format(node_name))

    def get_parents_names(self, name):
        parents = self.get_parents(name)
        names = [p.name for p in parents]
        return names

    # Returns the true value of a node
    def get_true_val(self, name):
        names = self.get_parents_names(name)
        c = Combinator(names)
        all_one = Combinator.get_all_one_combination(c.combinations)
        return self.diag.cpt(name)[all_one][1]




class Vertex:
  def __init__(self, id, text, type,  number):
    self.id = str(id)
    self.text = text 
    self.type = type 
    self.number = number
    self.tid_id = None
    if self.is_tid():
      self.tid_id = self.extract_tid_id()

  def is_leaf(self):
    return self.type == "LEAF"

  def is_and(self):
    return self.type == "AND"

  def is_or(self):
    return self.type == "OR"

  def is_tid(self):
    return "tid" in self.text 

  def extract_tid_id(self):
      return re.sub("\(.*?\)", "", self.text)

  def is_final_tid(self):
    return self.tid_id == "tid17" or self.tid_id == "tid02"

  def __str__(self):
    return "id = {}, text = {}, type = {}".format(self.id, self.text, self.type)

  def find_by_id(vertices, v_id):
    for v in vertices:
      if v.id == v_id:
        return v.get_name()
    return None

  def find_obj_by_id(vertices, v_id):
    for v in vertices:
      if v.id == v_id:
        return v
    return None

  def find_by_threat_id(vertices, v_id):
    for v in vertices:
      if v.tid_id == v_id:
        return v.get_name()
    return None
  def find_by_name(vertices, name):
      for v in vertices:
          if name == v.get_name():
              return v
      return None

  def disallowed_in_graph(self):
    return self.is_leaf() and not self.is_tid()


  def get_threats(vertices):
      return [v for v in vertices if v.is_tid()]

  def get_name(self):
    return "{}-{}".format(self.id, self.text)

  def from_csv(f):
    ret = []
    with open(f) as csv_file:
      csv_reader = csv.reader(csv_file, delimiter=',')
      for row in csv_reader:
        v = Vertex(row[0], row[1], row[2], row[3])
        # TODO: Other conditions
        if v.disallowed_in_graph() :
            p("Skipped {}".format(v.get_name()))
        else:
            ret.append(v)
    return ret

class Arc:
    def __init__(self, src, dest):
        self.src = src
        self.dest = dest 

    def from_csv(f, vertices):
      ret = []
      with open(f) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            src = Vertex.find_obj_by_id(vertices, row[1])
            dst = Vertex.find_obj_by_id(vertices, row[0])
            # When we skip vertices, we add here
            if src != None and dst != None:
                a = Arc(src, dst)
                ret.append(a)
      return ret



# class FinalSC:
#     def is_tid_final(id):
        # return id == 



class ThreatImpact:
    def __init__(self, tid, impact):
        self.tid = tid
        self.impact = impact


class SecThreatBenefit:
    def __init__(self, threat, sc, threat_benefit):
        self.threat = threat
        self.sc = sc
        self.threat_benefit = threat_benefit
        print("sc cost: {}".format(self.sc.cost))
        print("threat benefit: {}".format(threat_benefit))
        print("threat cost: {}".format(threat.impact))

    def sc_implemented_no_threat(self):
        # The sc is implemented but no threat

        return -self.sc.cost 

    def sc_implemented_threat(self):
        # The sc is implemented and threat occurs
        return self.threat_benefit  - self.sc.cost - self.threat.impact

    def sc_no_implemented_threat(self):
        # The sc is not implemented and threat
        return - self.threat.impact
    def sc_no_implemented_no_threat(self):
        # The sc is not implemented and threat
        return 0
    def get_name(self):
        return self.sc.name + "-against-" + self.threat.tid

    def get_full_name(self):
        return "Utility: "+ self.sc.name + "against" + self.threat.tid


class SecurityControl:
    def __init__(self, name, cost):
       self.name = name
       self.cost = cost
       self.addressed_threats = []

    def add_threat(self, threat, threat_benefit):
        self.addressed_threats.append(SecThreatBenefit(threat, self, threat_benefit))


class Threat:
    def __init__(self, tid, description, p):
        self.tid = tid
        self.description = description
        self.p = p

    def get_by_id(threats, tid):
        for t in threats:
            if t.tid == tid: 
                return t
        return None
    
    def from_csv(f):
        ret = []
        with open(f) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                tid = row[0].replace("_", "").lower()
                descr = row[1]
                p = float(row[4])
                ret.append(Threat(tid, descr, p))
        return ret



#     def get_combinations(nodes_cpts):
#         for n in nodes_cpts:


    # def get_cpt(self):
        



