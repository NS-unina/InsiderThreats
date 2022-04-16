import pandas as pd
import ujson
import csv
import json
class Threat:
    def __init__(self, tid, keyword, description, p):
        self.tid            = tid
        self.keyword        = keyword
        self.description    = description
        self.p              = p

    def get_by_id(threats, tid):
        if tid is None:
            raise Exception("tid cannot be null")
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


df = pd.read_csv('scAssociation.csv')
threats = Threat.from_csv('thid.csv')
sec_controls = []
for i, row in df.iterrows():
    sc = {}
    cis_id = row[0]
    print("CIS {}".format(cis_id))
    cis_descr = row[1]
    tids = row[2].split("-")
    sc[cis_id] = {
        'descr' : cis_descr,
        'addressed_threats' : []
    }
    for t in tids:
        real_threat = Threat.get_by_id(threats, t)
        print(real_threat.tid)
        sc[cis_id]['addressed_threats'].append({
            'tid'       : real_threat.tid,
            'keyword'   : real_threat.keyword,
            # 'prob'      : real_threat.p
        })

    sec_controls.append(sc)
with open('json_sc.json', 'w') as outfile:
    ujson.dump(sec_controls, outfile)

# df.to_json('scAssociation.json')