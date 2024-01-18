import os
from pathlib import Path

paths = Path('experiments/PCGF/gen_TFPP_traffic/test_TFPP_traffic/events').glob('*')
path_time = [(p, os.path.getmtime(p)) for p in paths].sort(key=lambda pair: pair[1])

path2time = {p: os.path.getmtime(p) for p in events_paths}

for path in event_files:
  print