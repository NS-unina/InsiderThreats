import sys

import random
import string

def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


class InputFile:
    def __init__(self):
        with open('input.P', 'r') as i:
            self.lines =i.readlines()

    def add_unaware(self, name):
        s = "unawareness({}).\n".format(name)
        self.lines.insert(0, s)


    def add_physical_threat(self, attacker, victim_workstation):
        s = "hasPhysicalAccess({}, {}).\n".format(attacker, victim_workstation)
        s2 = "dataInAsset({}, data).\n".format(victim_workstation)
        self.lines.insert(0, s)
        self.lines.insert(0, s2)

    def update(self):
        with open('input.P', 'w') as fw:
            fw.writelines(self.lines)


        

# def update()
# def add_unaware(name):

attacker = get_random_string(8)
workstation = get_random_string(4)
input_file = InputFile()
input_file.add_physical_threat(attacker, "daniel_workstation")
input_file.update()
