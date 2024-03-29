import pandas as pd
import sys
import os
from pathlib import Path
import subprocess
from datetime import datetime
import time




try:
    PACE_PATH = os.getenv('PACE_PATH')
    if PACE_PATH is None:
        print("Plese configure PACE_PATH environment variable")
        exit(-1)


except KeyError:
    print("Plese configure PACE_PATH environment variable")
    exit(-1)

def employee(r):
    return int(r['Employees'])
def admin(r):
    return int(r['Admins'])
def assets(r):
    return int(r['Assets'])
def disclosure(r):
    return int(r['Disclose'])
def ransom(r):
    return int(r['Ransomware'])


def time_millis():
    obj = time.gmtime(0)
    epoch = time.asctime(obj)
    curr_time = round(time.time()*1000)
    return curr_time



def generate_command(r, name):
    return "python threat_graph_generator.py {} --employees {} --admins {} --assets {} --ransom {} --disclose {}".format(name, employee(r), admin(r), assets(r), disclosure(r), ransom(r))

def gen_graph(experiment_name):
    print(experiment_name)
    return "cd ../threat_graph && cd {} && graph_gen.sh -r rules.P input.P -v > /dev/null 2>&1 ".format(experiment_name)

def get_treewidth(experiment_name):
    # print(experiment_name)
    return "cd ../threat_graph && cd {} && graph_gen.sh -r rules.P input.P -v > /dev/null 2>&1 && cd .. && python graph.py {} > graph.gr && cp graph.gr {} && cd {} && ./treewidth.sh".format(experiment_name, experiment_name, PACE_PATH, PACE_PATH)

if __name__ == "__main__":
    df = pd.read_csv('Full_factorial_design.csv')
    start = 0
    if len(sys.argv) >= 2: 
        start = int(sys.argv[1])
        print("[+] Start from{}".format(start))

    output_df = pd.DataFrame(columns = ['Employees', 'Admins', 'Assets', 'Disclose', 'Ransomware', 'Time'])

    for index, row in df.iterrows():
        # print("Index: {}".format(index))
        if index >= start and index < 3:
            experiment_name = "experiment_{}".format(index)
            print("Generate {}".format(experiment_name))

            py_command = generate_command(row, experiment_name)
            os.system(py_command)

            
            start_time = time_millis()
            subprocess.check_output(gen_graph(experiment_name), shell=True)
            end_time = time_millis()
            interval = end_time - start_time
            print("Time required: {}".format(interval))

            # treewidth = int(subprocess.check_output(get_treewidth(experiment_name), shell=True))
            df_row = pd.DataFrame.from_dict({'Employees' : [employee(row)], 'Admins': [admin(row)], 'Assets': [assets(row)], 'Disclose': [disclosure(row)], 'Ransomware' : [ransom(row)], 'Time': [interval]})
                # f.write("{},{},{},{},{},{},{}\n".format(index, employee(row), admin(row), assets(row), disclosure(row), ransom(row), treewidth))
            output_df = pd.concat([output_df, df_row], ignore_index=True)
    output_df.to_csv("results.csv")