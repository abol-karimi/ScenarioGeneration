#!/usr/bin/env python3.8
import matplotlib.pyplot as plt
import argparse
from src.scenariogen.core.mscatter import mscatter
from geomdl import operations

# This project
import scenariogen.core.seed as seed

parser = argparse.ArgumentParser(description='Plot frame-distance curve of a car.')
parser.add_argument('corpus', help='filename of the corpus of seeds')
parser.add_argument('seed', type=int, help='seed number to replay')
parser.add_argument('--resolution', type=int, default=701, help='Discretization resolution')
args = parser.parse_args()

# Load the seed
corpus = seed.SeedCorpus([])
corpus.load(args.corpus)
seed = corpus.seeds[args.seed]

# Sample the t-d curves
curves = seed.curves
frame2distance = []
for curve in curves:
    curve.sample_size = args.resolution
    frame2distance.append([p[1] for p in curve.evalpts])

fig, axs = plt.subplots(len(curves))
fig.suptitle('time-distance curves')
for j, curve in enumerate(curves):
    curve.sample_size = args.resolution
    axs[j].set_title(j)
    t = [p[0] for p in curve.evalpts]
    d = [p[1] for p in curve.evalpts]
    axs[j].plot(t, d)
    points = curve.ctrlpts
    t = [p[0] for p in points]
    d = [p[1] for p in points]
    mscatter(t, d, c='r', s=10, m='d', ax=axs[j])
plt.savefig('plot_t-d.png')
