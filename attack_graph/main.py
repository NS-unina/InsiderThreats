import csv
import pyAgrum as gum

vertices = []
arcs = []
thidProb = {}
arcsDict = {}
invArcsDict = {}

with open('inputData/VERTICES.CSV') as csv_file:
  csv_reader = csv.reader(csv_file, delimiter=',')
  for row in csv_reader:
    int(row[0])
    vertices.append(row)
    
with open('inputData/ARCS.CSV') as csv_file:
  csv_reader = csv.reader(csv_file, delimiter=',')
  for row in csv_reader:
    [int(i) for i in row]
    arcs.append(row)
    if row[0] in invArcsDict.keys():
      invArcsDict[row[0]].append(row[1])
    else:
      invArcsDict[row[0]] = []
      invArcsDict[row[0]].append(row[1])
    arcsDict[row[1]] = row[-1]

with open('probData/thid.csv') as csv_file:
  csv_reader = csv.reader(csv_file, delimiter=',')
  for row in csv_reader:
    thidProb[row[0]] = float(row[-1])

bn=gum.BayesNet('BayesianAttackGraph')

for row in vertices:
  bn.add(gum.LabelizedVariable(row[0],row[1],2))
for row in arcs:
  bn.addArc(row[1],row[0])



#print(thidProb)
#print(vertices)
