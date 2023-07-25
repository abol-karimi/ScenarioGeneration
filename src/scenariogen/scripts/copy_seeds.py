#!/usr/bin/env python3.8

# Standard libraries
import argparse

# My modules
import scenariogen.core.fuzz_input as seed

parser = argparse.ArgumentParser(description='Copy a subset of seeds from one corpus to another.')
parser.add_argument('in_corpus', 
                    help='the source corpus file')
parser.add_argument('out_corpus', 
                    help='the destination corpus file')
parser.add_argument('seeds', nargs='+', type=int, 
                    help='the list of indices of the seeds to copy')
args = parser.parse_args()

in_corpus = seed.SeedCorpus([])
in_corpus.load(args.in_corpus)
seeds = [in_corpus.seeds[i] for i in args.seeds]
out_corpus = seed.SeedCorpus(seeds=seeds, config=in_corpus.config)
out_corpus.save(args.out_corpus)
