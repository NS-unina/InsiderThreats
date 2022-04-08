# Insider Threat software 
The software that demonstrates the proposed model. 

## Insider Threat Graph  
`threat_graph` contains a mulval model for the insider threat proposed in the paper. 
A good guide to understand how to write a mulval model is give by:
https://github.com/fiware-cybercaptor/mulval/blob/master/doc/manual.md
Some information: 
* Each interaction_rule must be tabled and has a derived predicate.  
* utils/mulval_rules.P contains the list of rules provided by mulval (https://github.com/risksense/mulval/blob/master/kb/interaction_rules.P)
* If you wrong the syntax, mulval gives you hints about the error in `xsb_log.txt` file.
* The variable names in input must be written in undercase syntax, otherwise the program will generate `_` characters   
* The number parameter is not known