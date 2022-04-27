import csv
import matplotlib.pyplot as plt
from matplotlib import ticker
from model import *
from risk import *
from operator import itemgetter


result = []
bestResult = {}

def getScCombination(row):
    return row[0]

def getPerformance(row):
    return row[1]

def getRisk(row):
    return row[2]

def getCost(row):
    return row[3]

with open('result.csv', 'r') as file:
    reader = csv.reader(file)
    next(file)
    for row in reader:
        result.append([int(getScCombination(row)), float(getPerformance(row)), float(getRisk(row)), float(getCost(row))])
        #print(row)
        
#result = sorted(result, key=itemgetter(2))

for row in result:
    if float(getCost(row)) in bestResult:
        if bestResult[getCost(row)] > getRisk(row):
            bestResult[getCost(row)] = getRisk(row)
    else:
        bestResult[getCost(row)] = getRisk(row)


bestResult = dict(sorted(bestResult.items()))        
        
xValue = bestResult.keys()
yValue = list(bestResult.values())

#print(yValue)

fig = plt.figure()

plt.plot(xValue, yValue,'o',markersize=1)
plt.xlabel('Risk')
plt.ylabel('Cost')



fig.savefig("result.png")