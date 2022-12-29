import typer
import shutil
import os

import sys
from os import path
import pandas as pd

from random import randint



IMPACT_DISCLOSURE = "information_disclosure"
IMPACT_EXEC = "code_exec"

THREAT_PATH = os.path.join("..", "threat_graph")
BASE_PATH = os.path.join(THREAT_PATH, "base")

def get_value():
    values = [10, 100, 1000, 10000, 100000]
    return values[randint(0,4)]


def p(d):
    print(d)

# def usage():
#     print("[-] python graph.py <threat graph folder>")
#     sys.exit(-1)

def read_threat_graph(the_folder):
    with open(path.join(the_folder, "input.P"), 'r') as f: 
        lines = f.readlines()
    lines = [l.replace("\n", "") for l in lines ]
    lines = [l for l in lines if l]
    return lines

def find_data_lines(lines):
    data_lines = sorted(set([l for l in lines if "isDataStorage" in l]))
    ret = []
    for s in data_lines: 
        ret.append(s[s.find("(")+1:s.find(")")])
    return ret

def find_mail_lines(lines):
    data_lines = sorted(set([l for l in lines if "isSendingMail" in l]))
    ret = []
    for s in data_lines: 
        ret.append(s[s.find("(")+1:s.find(")")])
    ret = sorted(set([r.split(",")[1].strip() for r in ret]))

    return ret


def find_vuln_lines(lines):
    data_lines = sorted(set([l for l in lines if "vulExists" in l]))
    ret = []
    for s in data_lines: 
        ret.append(s[s.find("(")+1:s.find(")")])
    
    ret = sorted(set([r.split(",")[0].strip() for r in ret]))
    return ret




def read_base():
    with open("base.P", mode="r", encoding="utf-8") as file_handler:
        lines = file_handler.readlines()
        return "".join(lines)
        






def has_physical_access(attacker, asset):
    return "hasPhysicalAccess({}, {}).\n".format(attacker, asset)

def has_access(user, asset, permission):
    return "hasAccess({}, {}, {}).\n".format(user, asset, permission)


def add_vuln(name, asset, impact, isWeb = False):
    """Add a new vulnerability

    Args:
        name (str): the name of the vulnerability
        asset (str): the affected impact
        impact (str): the impact (vulnerability disclosure, code exec)
        isWeb (bool, optional): if the vulnerability is web. Defaults to False.
    """
    ret = ""
    if isWeb:
        ret = ret + "isWeb('{}').\n".format(name)
    else:
        ret = ret + "noWeb('{}').\n".format(name)
    ret = ret + "vulExists({}, '{}', {}).\n".format(asset, name, impact)
    return ret

class Asset:
    def __init__(self, name, is_public = False):
        self.name = name
        self.is_public = is_public

    def add_public_storage(self):
        return "isPublic({}).\n".format(self.name)

    def add_data_storage(self):
        return "isDataStorage({}).\n".format(self.name)

    def generate(self):
        ret = self.add_data_storage()
        if self.is_public: 
            ret = ret + self.add_public_storage()
        ret = ret + has_physical_access("Attacker", self.name)
        return ret
    

class Vulnerability:
    def __init__(self, name : str, asset : Asset, is_web = False, impact = IMPACT_DISCLOSURE):
        self.name = name
        self.asset = asset 
        self.is_web = is_web
        self.impact = impact

    def generate(self):
        return add_vuln(self.name, self.asset.name, self.impact, self.is_web)
    

class Employee:
    def __init__(self, name, is_administrator = False):
        self.name = name 
        self.is_administrator = is_administrator

    def unaware(self):
        return "unawareness({}).\n".format(self.name)
    def human_error(self):
        return "humanError({}).\n".format(self.name)
    def insider(self):
        return "insiderness({}).\n".format(self.name)
    def has_mail(self):
        return "hasMailAccount({}).\n".format(self.name)
    def is_sending_mail(self):
        return "isSendingMail({}, {}_mail).\n".format(self.name, self.name)
    def add_admin(self):
        return "isAdminOf({}, _).\n".format(self.name)

    def generate(self):
        ret = self.unaware() + self.human_error() + self.insider() + self.has_mail() 
        ret = ret + self.is_sending_mail() 
        if self.is_administrator:
            ret = ret + self.add_admin()

        return ret



class ThreatGraph:
    def __init__(self):
        self.model = ""
        self.assets = []
        self.vulnerabilities = []
        self.employees = []

    def add_asset(self, a: Asset):
        self.assets.append(a)
    def add_vuln(self, v: Vulnerability):
        self.vulnerabilities.append(v)

    def add_employee(self, e: Employee):
        self.employees.append(e)

    def generate(self):
        ret = ""
        if len(self.employees) > 0:
            for e in self.employees:
                ret = ret + e.generate()
                for a in self.assets: 
                    ret = ret + has_access(e.name, a.name, "exec")
                    ret = ret + a.generate()
        else: 
            for a in self.assets: 
                ret = ret + a.generate()
        
        for v in self.vulnerabilities:
            ret = ret + v.generate()

        ret = ret + read_base()
        return ret



    def append(self, v):
        self.model = self.model + v


def gen_employees(tg, no):
    for i in range(0, no):
        tg.add_employee(Employee("user{}".format(i), False))

def gen_administrators(tg, no):
    for i in range(0, no):
        tg.add_employee(Employee("administrator{}".format(i), True))

def gen_assets(tg, no):
    assets = []
    for i in range(0, no):
        a = Asset("asset_{}".format(i), True)
        tg.add_asset(a)
        assets.append(a)
    return assets

def gen_ransom(tg, a, no):
    for i in range(0, no):
        tg.add_vuln(Vulnerability("vuln_ransom_{}".format(i), a, False, IMPACT_EXEC))
def gen_disclosure(tg, a, no):
    for i in range(0, no):
        tg.add_vuln(Vulnerability("vuln_disclose_{}".format(i), a, True, IMPACT_DISCLOSURE))
        

def main(name: str, employees: int = typer.Option(1), admins: int = typer.Option(1), assets: int = typer.Option(1), ransom: int = typer.Option(0), disclose: int = typer.Option(0)):
    tg = ThreatGraph()
    the_path = os.path.join(THREAT_PATH, name)
    input_path = os.path.join(the_path, "input.P")
    # Create the test folder
    if not os.path.isdir(the_path):
        shutil.copytree(BASE_PATH,the_path) 

    # Create the scenario
    gen_employees(tg, employees)
    gen_administrators(tg, admins)
    assets = gen_assets(tg, assets)
    for a in assets: 
        gen_ransom(tg, a, ransom)
    for a in assets: 
        gen_disclosure(tg, a, disclose)

    with open(input_path, 'w') as f:
        f.write(tg.generate())

    # Generate fake asset records
    test_folder = the_path 
    lines = read_threat_graph(test_folder)
    data_lines = find_data_lines(lines)
    mail_lines = find_mail_lines(lines)
    vuln_lines = find_vuln_lines(lines)
    assets = data_lines + mail_lines + vuln_lines
    assets = sorted(set(assets))
    values = []
    for i in range(0, len(assets)):
        values.append(get_value())
    df = pd.DataFrame({'ASSET' : assets, 'RECORDS' : values})
    df.to_csv(path.join(test_folder, "asset_records.csv"), index=False)
    # print(tg.generate())


if __name__ == "__main__":
    typer.run(main)

    # e = Asset("elastic_search", True)
    # tg.add_asset(elk)

    # tg.add_vuln(Vulnerability("sqli", elk, False, IMPACT_EXEC))
    # print(tg.generate())



    # tg.add_asset(Asset("company_website"))
    # tg.add_vuln('SQLI', True, IMPACT_DISCLOSURE)
            

    # tg.append(add_admin("testadmin"))
    # tg.append(add_vuln('SQLI', "company_website", IMPACT_DISCLOSURE, True))

    # print(tg.model)
