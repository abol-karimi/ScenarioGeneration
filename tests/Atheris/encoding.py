#!/usr/bin/env python3
import sys
import atheris

# Load a seed, plot its trajectory
with open('experiments/seeds/random/seeds/4way-stop_autopilot/1a43dcb3623335496cfb43eb230ea711872349a2', 'rb') as f:
    seed_bytes = f.read()

# fdp = atheris.FuzzedDataProvider(seed_bytes)
# input_str = fdp.ConsumeUnicode(sys.maxsize)
# print(input_str)

input_str = seed_bytes.decode('utf-8')
print(input_str)