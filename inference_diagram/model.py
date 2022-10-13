import re
import json
import csv
from os import path
import pyAgrum as gum
import sys
from variables import *
from functools import reduce
from itertools import product

from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete.CPD import TabularCPD


def pr(s):
    print("[+] {}".format(s))

def dbg(s):
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
        # return len(self.diag.children(id)) == 0
        return len(self.diag.get_children(node = id)) == 0

    def is_root_node(self, id):
        # return len(self.diag.parents(id)) == 0
        return len(self.diag.get_parents(node = id)) == 0

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
        names = diag.nodes()
        gum_nodes = []
        for n in names:
            # the_id = diag.idFromName(n)
            the_id = n
            v = Vertex.find_by_name(vertices, n)
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
            # self.diag = gum.BayesNet('BayesianThreatGraph')
            self.diag = BayesianNetwork()
        else:
            self.diag = diag
            #self.nodes = GumNode.generate_nodes(self.diag)

    """
        Returns true until the no of set cpts is equal to number of nodes
    """
    def remaining_cpt(self):
        return len(self.cpt_setted) < self.no_nodes

    def has_parents(self, id):
        return len(self.diag.get_parents(node = id)) != 0

    def has_children(self, id):
        return len(self.diag.get_children(node = id)) != 0

    def get_root_nodes(self):
        return [n for n in self.nodes if n.is_root]

    def get_or_nodes(self):
      """
        Returns a list of OR nodes . It is used to generate the final threat graph
      """
      return [n for n in self.nodes if n.is_or]

    def get_goal_nodes(self):
        """ Returns a list of GUM Nodes

        Returns:
            list[GumNodes]: A list of gum nodes
        """
        return [n for n in self.nodes if n.is_leaf]

    def get_parents(self, name):
        parents = self.diag.get_parents(node=name)
        return [n for n in self.nodes if n.id in parents]

    def get_gum_node(self, name):
        return GumNode.find_by_name(self.nodes, name)

    def get_children(self, id):
        return self.diag.children(id)


    def generate_bayesian(self, vertices, arcs):
        dbg("Set vertices")
        for v in vertices:
            # self.diag.add(gum.LabelizedVariable(v.get_name(), v.text, 2))
            self.diag.add_node(v.get_name())
            self.no_nodes = self.no_nodes + 1
        dbg("Set arcs")
        dbg(len(arcs))
        i = 0
        for a in arcs:
            dbg("Add arcs")
            dbg(i)
            i = i +1
            self.diag.add_edge(a.src.get_name(), a.dest.get_name())
            # self.diag.addArc(a.src.get_name(), a.dest.get_name())
            self.no_arcs = self.no_arcs + 1
        dbg("Generate nodes")
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
        dbg("Generate \"AND\" cpt for {} node".format(variable_name))
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
        dbg("Generate \"OR\" cpt for {} node".format(variable_name))
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
        combinations = []
        evidences = []
        one = []
        two = []
        cname = ""
        for c in cpts:
            cc = list(c.combination.keys())
            for com in cc: 
                if com not in evidences:
                    evidences.append(com)
            # self.diag.cpt(node_name)[c.combination] = [c.prob.p_false, c.prob.p_true]
            one.append(c.prob.p_false)
            two.append(c.prob.p_true)
        print(evidences)
    
        values = [one, two]
        print(values)
        cpd = TabularCPD(
            variable = node_name, variable_card = 2, evidence = evidences, evidence_card = [2 for f in evidences], values=values
        )
        dbg("Add cpd")
        self.diag.add_cpds(cpd)


    def set_root_cpt(self, node_name, prob):
        if prob == None:
            raise Exception("Prob cannot be None")
        # Set cpt only if not already setted
        if node_name not in self.cpt_setted:
            cpd_node = TabularCPD(
                variable = node_name, variable_card = 2, values=[[1 - prob], [prob]]
            )
            self.diag.add_cpds(cpd_node)

            # self.diag.cpt(node_name).fillWith([1 - prob, prob])
            dbg("{} cpt configured".format(node_name))
            self.cpt_setted.append(node_name)
        else:
            dbg("{} already set!".format(node_name))

    def get_parents_names(self, name):
        parents = self.get_parents(name)
        names = [p.name for p in parents]
        return names

    # Returns the true value of a node
    def get_true_val(self, name):
        names = self.get_parents_names(name)
        c = Combinator(names)
        all_one = Combinator.get_all_one_combination(c.combinations)
        cpds = self.diag.get_cpds(node=name)
        return cpds.get_values()[1][0]
        
        # return self.diag.cpt(name)[all_one][1]




class Vertex:
  def __init__(self, id, text, type,  number):
    self.id = str(id)
    self.text = text
    self.type = type
    self.number = number
    self.tid_id = None
    if self.is_tid():
      self.tid_id = self.extract_tid_id()

  def extract_keyword(vertex_text):
        par_index = vertex_text.find('(')
        if par_index != -1 and "OR" not in vertex_text:
            return vertex_text[0:par_index]
        return None

  def is_threat_goal(self):
      return "TID_17" in self.text  or "TID_02" in self.text

  def is_final_node(self):
      """The final nodes that ends for "dataExfiltration" or "ransomwareAttack"

      Returns:
          Vertex: the final node
      """
      return "dataExfiltration" in self.text or "ransomware" in self.text

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
            dbg("Skipped {}".format(v.get_name()))
        else:
            ret.append(v)
    return ret

class Arc:
    def __init__(self, src, dest):
        self.src = src
        self.dest = dest

    def get_dest(arcs, src):
        for a in arcs:
            if a.src.id == src.id:
                return a.dest

    def set_dest(arcs, r, goal):
        for a in arcs:
            if a.src.id == r.id:
                a.dest = goal

    def get_parent_tid(arcs, g):
        for a in arcs:
            if a.dest.id == g.id and a.src.is_tid():
                return a.src

    def get_parent_no_tid(arcs, g):
        for a in arcs:
            if a.dest.id == g.id and not a.src.is_tid():
                return a.src

    def get_parents(arcs, g):
        """Get all parents of a node
        This is useful to generate OR conditions in the BTG

        Args:
            arcs (list): A list f nodes
            g (Vertex): The destination node

        Returns:
            Vertex: The source node
        """
        parents = []
        for a in arcs:
            if a.dest.id == g.id:
                parents.append(a.src)

        return parents



    def get_rules_arcs(rule_vertices, arcs):
        rule_arcs = []
        for r in rule_vertices:
            d = Arc.get_dest(arcs, r)
            rule_arcs.append(Arc(r, d))
        return rule_arcs




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
    def __init__(self, threat, keyword, sc_name, prob_reduction):
        self.threat = threat
        self.keyword = keyword
        self.sc = sc_name
        self.prob_reduction = prob_reduction

    # def sc_implemented_no_threat(self):
    #     # The sc is implemented but no threat

    #     return -self.sc.cost

    # def sc_implemented_threat(self):
    #     # The sc is implemented and threat occurs
    #     return self.threat_benefit  - self.sc.cost - self.threat.impact

    # def sc_no_implemented_threat(self):
    #     # The sc is not implemented and threat
    #     return - self.threat.impact
    # def sc_no_implemented_no_threat(self):
    #     # The sc is not implemented and threat
    #     return 0
    def get_name(self):
        return self.sc + "-against-" + self.threat.tid

    def get_full_name(self):
        return "Utility: "+ self.sc +  "against" + self.threat.tid


class SecurityControlManager:
    """ This class select a subset of security controls depending on a binary vector
    """

    def __init__(self, security_controls):
        self.security_controls = security_controls
        # [0,0,0,0,...],[0,0,0,....]
        self.combinations = list(product([0, 1], repeat=len(security_controls)))

    def get_implementation_cost(self, subset):
        """Return the implementation cost by summing all the SC costs

        Args:
            subset (List): The subset of implemented security controls
        """
        implementation_cost = sum([s.cost for s in subset])
        return implementation_cost


    def get_no_combinations(self):
        return len(self.combinations)

    def get_subset(self, no):
        """Returns the relative subset of security controls from the combination
        Args:
            no (int): the nth subset combination

        Returns:
            List<SecurityControls>: The list of chosen security controls
        """
        nth_combination = self.combinations[no]
        subset_security_controls = []
        for index in range (0, len(nth_combination)):
            # Append only if the value of the binary vector is 1
            if nth_combination[index] == 1:
                subset_security_controls.append(self.security_controls[index])

        return subset_security_controls


class SecurityControl:
    def __init__(self, name, cost, addressed_threats = []):
       self.name = name
       self.cost = float(cost)
       self.addressed_threats = addressed_threats

    def add_threat(self, threat, prob_reduction):
        self.addressed_threats.append(SecThreatBenefit(threat, self, prob_reduction))

    def address_threat(self, threat):
        """ The methods returns true if the security control address a specific threat

        Args:
            threat (Threat): A Threat object

        Return: True if the threat is addressed
        """
        for a in self.addressed_threats:
            if a.keyword == threat.keyword or a.threat == threat.tid:
                return True
        return False

    def get_threat_benefit(self, threat):
        for a in self.addressed_threats:
            if a.keyword == threat.keyword or a.threat == threat.tid:
                return a
        raise Exception("The threat is not addressed")

    def get_threat_benefits(security_controls, t):
        """ Return the threat benefit stored in the security control that address the threat
        Args:
            security_controls (List): The list of sec controls
            t (Threat): A threat object

        Return the threat benefits for that threat
        """
        ret = []
        for s in security_controls:
            if s.address_threat(t):
                threat_benefit = s.get_threat_benefit(t)
                ret.append(threat_benefit)
        return ret



    def from_json(json_path):
        security_controls = []
        with open(json_path) as f:
            data = json.load(f)
            for d in data:
                cis_name = list(d.keys())[0]
                info = d[cis_name]
                addressed_threats = []
                for t in info['addressed_threats']:
                    tid = t['tid']
                    keyword = t['keyword']
                    probReduction = float(t['probReduction'])
                    benefit = SecThreatBenefit(tid, keyword, cis_name, probReduction)
                    addressed_threats.append(benefit)

                sc = SecurityControl(cis_name, info['cost'], addressed_threats)
                security_controls.append(sc)
        return security_controls




class Threat:
    def __init__(self, tid, keyword, description, p):
        self.tid = tid
        self.keyword = keyword
        self.description = description
        self.p = p

    def apply_threat_benefits(self, threat_benefits):
        """ Apply the threat benefits that reduce the probability
        For each threat benefit obtained by the security controls that address the threat,
        reduce the threat.
        Args:
            threat_benefits (List): The list of threat benefits that reduce the threat probability
        """
        dbg("Apply threat reduction for {}".format(self.tid))
        for tb in threat_benefits:
            prob_reduction = tb.prob_reduction
            dbg("Apply prob reduction of {}".format(prob_reduction))
            old_prob = self.p
            self.p = prob_reduction * self.p
            dbg("Old prob: {} New: {}".format(old_prob, self.p))

        if len(threat_benefits) > 0:
            dbg("Reduced probability: {}".format(self.p))


    def get_by_id(threats, tid):
        if tid is None:
            raise Exception("tid cannot be null")
        # or "TID_{}".format(t.description.replace("tid", "")):
        for t in threats:
            if t.tid == tid:
                return t
        else:
            raise Exception("Tid not found")

    def from_csv(f):
        ret = []
        with open(f) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                # TID_X => tidx
                tid = row[0].replace("_", "").lower()
                keyword = row[1]
                descr = row[2]
                p = float(row[5])
                ret.append(Threat(tid, keyword, descr, p))
        return ret


    def is_vector_threat(threats, vertex_text):
        ret = False
        if Threat.get_vector_threat(threats, vertex_text):
            ret = True
        return ret

    def get_vector_threat(threats, vertex_text):
        ret = None
        for t in threats:
            keyword = Vertex.extract_keyword(vertex_text)
            if keyword:
                if keyword == t.keyword and t.keyword != "dataExfiltration" and t.keyword != "ransomwareAttack":
                    ret = t
        return ret




#     def get_combinations(nodes_cpts):
#         for n in nodes_cpts:


    # def get_cpt(self):




