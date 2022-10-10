cp performance/ARCS.CSV complete/
cp performance/VERTICES.CSV complete/
start=$(date +%s)
# python run_generate_btg.py
python run_single.py
end=$(date +%s)
echo "$(($end-$start))" > spent_time.txt

