

class ThreatImpact:
    def __init__(self, tid, impact):
        self.tid = tid
        self.impact = impact


class SecThreatBenefit:
    def __init__(self, threat, sc, threat_benefit):
        self.threat = threat
        self.sc = sc
        self.threat_benefit = threat_benefit

    def sc_implemented_no_threat(self):
        # The sc is implemented but no threat
        return -self.sc.cost - self.threat.impact

    def sc_implemented_threat(self):
        # The sc is implemented and threat
        return self.threat_benefit  - self.sc.cost - self.threat.impact

    def sc_no_implemented_threat(self):
        # The sc is not implemented and threat
        return - self.threat.impact
    def sc_no_implemented_no_threat(self):
        # The sc is not implemented and threat
        return 0
    def get_name(self):
        return self.sc.name + " against " + self.threat.tid


class SecurityControl:
    def __init__(self, name, cost):
       self.name = name
       self.cost = cost
       self.addressed_threats = []

    def add_threat(self, threat, threat_benefit):
        self.addressed_threats.append(SecThreatBenefit(threat, self, threat_benefit))


