from ast import parse
from risk import *

def test_parse_goal():
    assert parse_goal_name("53-ransomwareAttack(dns_server)") == "dns_server"
    assert parse_goal_name("53-ransomwareAttack(daniel, dns_server)") == "dns_server"