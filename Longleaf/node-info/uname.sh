volta_nodes=(dgx01 dgx02 dgx03 g0301 g0302 g0303 g0304 g0305 g0306 g0307 g0308 g0309 g0310 g0311 g0312 g0313 g0314 g0315 g0316)
for node in ${volta_nodes[@]}; do
  sbatch \
    -p volta-gpu \
    -w $node \
    --cpus-per-task=1 \
    --qos gpu_access \
    --gres=gpu:0 \
    --mem=2G \
    -o "${node}_uname.txt" \
    -t 00:01:00 \
    --wrap="uname -a"
done

 