from variables import * 
from model import * 
def test_extract_keyword_from_text():
    no = "OR for dataExfiltration(data,administrator_mail)"
    no_two = "ransomwareAttack(dns_server)"
    no_three = "dataExfiltration(data,company_website)"
    yes = "webDisclosureVulnerability(company_website,'SQLi')"
    wrong = "wrong"
    threats = Threat.from_csv(folder_data(TID_FILE))

    assert Vertex.extract_keyword(yes) == "webDisclosureVulnerability"
    assert Vertex.extract_keyword(no) == None
    assert Vertex.extract_keyword(no_two) == "ransomwareAttack"
    assert Vertex.extract_keyword(no_three) == "dataExfiltration"
    assert Vertex.extract_keyword(wrong) == None

def test_is_vector_threat():
    no = "OR for dataExfiltration(data,administrator_mail)"
    no_two = "ransomwareAttack(dns_server)"
    no_three = "dataExfiltration(data,company_website)"
    yes = "webDisclosureVulnerability(company_website,'SQLi')"
    threats = Threat.from_csv(folder_data(TID_FILE))

    assert Threat.is_vector_threat(threats, yes) == True
    assert Threat.is_vector_threat(threats, no) == False
    assert Threat.is_vector_threat(threats, no_two) == False
    assert Threat.is_vector_threat(threats, no_three) == False
