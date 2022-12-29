#!/bin/bash
WIDTH=`./tw-exact < graphs/graph.gr | head -1 | cut -f4 -d" "`
echo $(($WIDTH-1))