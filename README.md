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
* The number parameter is not known .
*  DO NOT USE DOUBLE POINT IN rule_descr: it will break everything.      

### Information   
The main files are *input.P* and *rules.P*. 
* input.P contains the model   
* rules.P contains the rules that allows for the generation of the attack graph    

### How to generate the output   
To build the attack graph, go in the folder and run the `Makefile` script:  
```  
make gen 
# or, if you want the pdf graphical view   
make graph   
```     

It will generate the files useful for the inference diagram:   
* ARCS.CSV: the list of relationships between nodes   
* VERTICES.CSV: the description of each node    

## Inference diageram   
The inference diagram folder contains the source code to run the risk management inference algorithm.   
To run the algoruthm:    
* put the ARCS.csv and the VERTICES.CSV in the `complete` folder   
* run `python run_generate_btg.py`  

### variables   
variables.py contains variables that can be changed to setup the environment:  
* VERTICES_FILE       : the vertices file obtained by the attack graph generation algorithm. 
* ARCS_FILE           : the arcs file obtained by the attack graph generation algorithm.  
* TID_FILE            : the threat model file 
* ASSETS_FILE         : the assets file
* SC_ASSOCIATION_FILE : the security control association file
* IS_SIMPLIFIED       : if you want to use the simplified model
* DEBUG: when True, the library prints all debug information
