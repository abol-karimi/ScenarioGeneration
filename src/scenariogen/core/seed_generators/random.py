"""
Generates random seeds using simulation.
1. A random route through the intersection is chosen for the VUT.
2. A random number of non-egos with random routes through the intersection are chosen.
3. All the vehicles (VUT and non-egos) are driven using the VUT's algorithm.
"""

from pathlib import Path
import jsonpickle
from random import Random
from functools import cache

from scenic.domains.driving.roads import Network

# This project
from scenariogen.core.utils import extend_lane_forward, turns_from_route, seed_from_sim
from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.core.fuzz_input import FuzzInput
from scenariogen.core.coverages.coverage import StatementSetCoverage, PredicateSetCoverage, PredicateCoverage, StatementCoverage
from scenariogen.core.errors import InvalidFuzzInputError, CoverageError
from scenariogen.core.fuzzing.runner import SUTRunner, SimResult
from .base import Fuzzer


class RandomSeedGenerator(Fuzzer):

  def __init__(self, config):
    self.config = config
    self.feature_coverage = StatementSetCoverage([])
    self.random = Random(config['randomizer-seed'])  

    self.network = Network.fromFile(config['map'])
    self.intersection = self.network.elements[config['intersection']]

    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
      self.blueprint2dims = jsonpickle.decode(f.read())
    self.blueprints = tuple(self.blueprint2dims.keys())

  def get_state(self):
    state = {
      'coverage-seen': self.feature_coverage,
      'random-state': self.random.getstate(),
      }
    return state

  def set_state(self, state):
    self.feature_coverage = state['coverage-seen']
    self.random.setstate(state['random-state'])

  def input_eval(self, fuzz_input, SUT_config, coverage_config, save_events=True):
    sim_result = SUTRunner.run({**SUT_config,
                                **coverage_config,
                                **fuzz_input.config,
                                'fuzz-input': fuzz_input,
                                })
    if (not sim_result is None) and 'coverage' in sim_result.records:
      # For debugging purposes, save events
      if save_events:
        with open(Path(self.config['events-folder'])/f'{fuzz_input.hexdigest}.json', 'w') as f:
            f.write(jsonpickle.encode(sim_result.records['events'], indent=1))

      return sim_result.records['coverage']
    else:
      return None
    
  def gen_input(self):
    """TODO Randomly sample from an input parameter space"""
    # config = {}
    # blueprints = []
    # routes = []
    # footprints = []
    # timings = []
    # signals = []



    # nonegos_count = self.random.randint(1, self.config['max-nonegos'])
    # for i in range(nonegos_count):
    #   blueprint = self.random.choice(*self.blueprints)
    #   init_lane = self.random.choice(*self.intersection.incomingLanes, *self.intersection.outgoingLanes)
    #   x0 = self.random.uniform(1, init_lane.centerline.length-3)
    #   ext = extend_lane_forward(init_lane, self.config['min-route-length'] - init_lane.centerline.length + x0, self.random)
    #   lanes = (init_lane,) + tuple(ext)
    #   turns = turns_from_route(lanes)
    #   route = tuple(l.uid for l in lanes)
    #   transform = CurvilinearTransform([p for lane in lanes
    #                                       for p in lane.centerline.lineString.coords
    #                                       ])
    # sim_result = SimResult(trajectory=trajectory, records=records)
    # fuzz_input = seed_from_sim(sim_result, self.config['timestep'], self.config['spline-degree'])
    # return fuzz_input
    pass

  def run(self):
    fuzz_input = self.gen_input()
    statement_coverage = self.input_eval(fuzz_input, self.config['coverage-config'])
    if (not statement_coverage is None) and not statement_coverage in self.feature_coverage:
      self.feature_coverage = self.feature_coverage + StatementSetCoverage([statement_coverage])
      
      # Save the fuzz-input and its coverage to disk
      with open(Path(self.config['fuzz-inputs-folder'])/f'{fuzz_input.hexdigest}.json', 'wb') as f:
        f.write(fuzz_input.bytes)
      with open(Path(self.config['coverages-folder'])/f'{fuzz_input.hexdigest}.json', 'w') as f:
        f.write(jsonpickle.encode(statement_coverage, indent=1))
      
      print(f'The fuzzed input with hash {fuzz_input.hexdigest} expanded the coverage! Added input to the corpus.')

    return statement_coverage

