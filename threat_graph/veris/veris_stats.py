from cgi import print_environ_usage
import pandas as pd
import sys
import numpy as np

ACTOR = 'Actor'
SYSTEM_INTRUSION = 'pattern.System Intrusion'
WEB_ATTACK = 'pattern.Basic Web Application Attacks'
def account_compromission():
    with open('account_compromission.txt', 'r') as r:
        data = [a.strip() for a in r.readlines()]
    return data

def other_threats():
    with open('sorted_other.txt', 'r') as r:
        data = [a.strip() for a in r.readlines()]
    return data




def e():
    sys.exit(-1)

def p(v):
    print("[+] {}".format(v))

def num_rows(veris):
    return veris.shape[0]

def _get_where(veris, d, v):
    return veris.loc[veris[d] == v]

def get_external(veris):
    return _get_where(veris, ACTOR, 'External')

def get_ids(veris):
    return veris['incident_id']

def get_system_intrusion(veris):
    return _get_where(veris, SYSTEM_INTRUSION, True)

def get_web_application(veris):
    return _get_where(veris, WEB_ATTACK, True)

def check_web_in_intr(ids_web, ids_intr):
    intr_vals = ids_intr.values
    web_vals = ids_web.values
    # print("web that are also in intr")
    # print([w for w in web_vals if w in intr_vals])
    # print("intr: {}".format(len(intr_vals)))
    print("In intr not in web")
    intr_not_web = [w for w in intr_vals if w not in web_vals]
    # print(len(intr_not_web))
    # print(intr_not_web)
    # print("In web not in intr")
    # print(len([w for w in web_vals if w not in intr_vals]))




veris = pd.read_csv('2020.csv')
external = get_external(veris)
ids_external = get_ids(external)
ot = other_threats()





web_app = get_web_application(external)
intrusions = get_system_intrusion(external)
ids_web = get_ids(web_app)
ids_intr = get_ids(intrusions)
compromissions = account_compromission()
web_compromission = [w for w in ids_intr if w in compromissions]
# p(len(web_compromission))


ids_tot_intrusion = pd.unique(pd.concat([ids_intr, ids_web]))
# wv = list(ids_web.values)
# iv = list(ids_intr.values)
# print(len(sorted(set(iv + wv))))
# print(len(ids_web.values))
# print(len(ids_intr.values))
# print(len(ids_tot_intrusion))
total_intrusions = external.loc[external['incident_id'].isin(ids_tot_intrusion)]
print(total_intrusions.shape[0])
num_external = len(ids_external.values)
num_web = len(ids_web.values)
num_intr = len(ids_intr.values) 
p("Num intrusions: {}".format(num_external))
p("Num web: {}".format(num_web))
p("Num intr: {}".format(num_intr))
# p(ids_intr.values)

p("Others: {}".format(num_external - num_web - num_intr))

# print(total_intrusions)

# ids_no_web = ids_external[ids_external.isin(ids_web)]
# check_web_in_intr(ids_web, ids_intr)
no_intrusion = external.loc[~external['incident_id'].isin(ids_tot_intrusion)]
print(no_intrusion.shape[0])
no_other = no_intrusion.loc[~no_intrusion['incident_id'].isin(ot)]
print(no_other.shape[0])
e()
# no_intrusion.to_csv('new.csv')
ids = get_ids(no_intrusion)
print(len(ids.values))
# ids.to_csv('ids.csv')

# print(total_intrusions)
# print(ids)
# print(no_intrusions)
