from pathlib import Path
import jsonpickle

from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError

def from_corpus(SUT_config, corpus_folder):
  coverage_sum = set()
  pathlist = Path(corpus_folder).glob('*.json')
  for path in pathlist:
    with open(path, 'r') as f:
      seed = jsonpickle.decode(f.read())
      seconds = seed.timings[0].ctrlpts[-1][0]
    try:
      sim_result = Scenario(seed).run({**SUT_config,
                                       'steps': int(seconds // SUT_config['timestep'])})
    except NonegoNonegoCollisionError as err:
      print(f'Collision between nonegos {err.nonego} and {err.other}.')
    except EgoCollisionError as err:
      print(f'Ego collided with {err.other}.')
    else:
      coverage_space = sim_result.records['coverage_space']
      coverage_sum.update(sim_result.records['coverage'])

  return coverage_space, coverage_sum