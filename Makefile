PATHSEP2=/
PATH_ONE := $(CURDIR)$(PATHSEP2)threat_graph$(PATHSEP2)evaluation$(PATHSEP2)company_one
PATH_TWO := $(CURDIR)$(PATHSEP2)threat_graph$(PATHSEP2)evaluation$(PATHSEP2)company_two
PATH_THREE := $(CURDIR)$(PATHSEP2)threat_graph$(PATHSEP2)evaluation$(PATHSEP2)company_three
TREEWIDTH := ./tw-exact < graph.gr | head -1 | cut -f4 -d" "
NO_VERTS := cat test/VERTICES.CSV | wc -l | xargs
NO_EDGES := cat test/ARCS.CSV | wc -l | xargs
PACE_PATH := ~$(PATHSEP2)git$(PATHSEP2)unina$(PATHSEP2)PACE2017-TrackA

eval_one:
	cd inference_diagram && python run_generate_btg.py $(PATH_ONE)

test_evaluation:
	cd threat_generator && python threat_graph_generator.py > ../threat_graph/test/input.P
	cd threat_graph/test && make graph
	cd threat_graph && python generate_fake_assets.py test
	cd threat_graph && python graph.py test  > graph.gr && cp graph.gr $(PACE_PATH) && cd $(PACE_PATH) &&  echo "Treewidth: `./treewidth.sh`"
	cd threat_graph && echo "Vertices = `$(NO_VERTS)`"
	cd threat_graph && echo "Edges = `$(NO_EDGES)`"
	cd inference_diagram && stat-exec "python run_generate_btg.py ../threat_graph/test"

	