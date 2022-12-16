# cp performance/ARCS.CSV complete/
# cp performance/VERTICES.CSV complete/
nowInMs() {
  echo "$(($(date +'%s * 1000 + %-N / 1000000')))"
}
start="$(nowInMs)"
# python run_generate_btg.py
python run_single.py
end="$(nowInMs)"
echo "$(($end-$start))" > spent_time.txt

