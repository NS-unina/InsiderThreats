"""
    A module containing impact information
"""
import numpy as np
import math
import pandas as pd
from model import *


def lossFunction(no_records):
    """The function relates the number of breached records with the financial impact

    Args:
        no_records (int): the number of records

    Returns:
        impact_in_dollars: the impact damage
    """
    q = 10.36163292
    m = 0.55216548
    return np.exp(q+m*math.log(no_records))


def parse_goal_name(s):
    ret = s[s.find('(')+1:s.find(')')]
    splitted = ret.split(',')
    return splitted[-1].strip()


class AssetImpact:
    def __init__(self, asset, no_records):
        self.asset = asset
        self.no_records = no_records

    def get_security_incident_loss(self):
        """
        Returns the financial loss after a security incident
        """
        return lossFunction(self.no_records)

    def from_csv(fullpath):
        assets = []
        df = pd.read_csv(fullpath)
        for i, row in df.iterrows():
            asset = AssetImpact(row[0], row[1])
            assets.append(asset)

        return assets

    def get_from_goal(assets, goal_name):
        """ Parse a node name generated by Mulval and returns the asset

        Args:
            assets (list): The asset list
            goal_name (str): The goal name
        """

        host_name = parse_goal_name(goal_name)
        for a in assets: 
            if a.asset == host_name:
                return a
        raise Exception("Asset {} not found".format(host_name))


class Risk:
    def __init__(self, threat_prob, loss):
        self.threat_prob    = threat_prob 
        self.loss           = loss
    def risk(self):
        return self.threat_prob * self.loss


    def total(risks):
        """The total risk is given by the sum of threat risks 

        Args:
            risks (_type_): _description_

        Returns:
            _type_: _description_
        """
        total = 0
        for r in risks:
            total = total + r.risk()
        return total





