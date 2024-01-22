#!/usr/bin/env python3.8
import matplotlib.pyplot as plt
import argparse
from scenariogen.core.mscatter import mscatter
from geomdl import operations
from scenariogen.core.utils import sample_trajectory

# This project
import scenariogen.core.fuzz_input as seed

parser = argparse.ArgumentParser(description='Plot frame-distance curve of a car.')
parser.add_argument('corpus', help='filename of the corpus of seeds')
parser.add_argument('fuzz-input', type=int, help='seed number to replay')
parser.add_argument('--resolution', type=int, default=701, help='Discretization resolution')
args = parser.parse_args()

# Load the seed
corpus = seed.SeedCorpus([])
corpus.load(args.corpus)
seed = corpus.seeds[args.seed]

# Sample the splines
splines = seed.curves
sample_size = args.resolution
fig = plt.figure()
fig.suptitle('spacetime trajectories')
ax3d = fig.add_subplot(211, projection='3d')
ax3d.set_title('3D')
ax3d.view_init(elev=90, azim=0, roll=0)
for i, spline in enumerate(splines):
  spline.sample_size = sample_size
  x = [p[0] for p in spline.evalpts]
  y = [p[1] for p in spline.evalpts]
  t = [p[2] for p in spline.evalpts]
  ax3d.plot(x, y, t)
  
plt.savefig('plot_3d.png')
