import sys
from os import path
import pandas as pd

from random import randint

def get_value():
    values = [10, 100, 1000, 10000, 100000]
    return values[randint(0,4)]


def p(d):
    print(d)
def usage():
    print("[-] python graph.py <threat graph folder>")
    sys.exit(-1)

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




    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    test_folder = sys.argv[1]
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
