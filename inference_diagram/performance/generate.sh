NO_ADD=7
for i in $(seq 1 $NO_ADD);
do
    # r=`echo $RANDOM | md5sum | head -c 20; echo;`
    # r2=`echo $RANDOM | md5sum | head -c 20; echo;`
    python generator.py 
done
make graph