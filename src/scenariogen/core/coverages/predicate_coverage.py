from pathlib import Path
import jsonpickle

from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError

def from_corpus(corpus_folder, config={}):
  coverage_sum = set()
  pathlist = Path(corpus_folder).glob('*.json')
  for path in pathlist:
    with open(path, 'r') as f:
      fuzz_input = jsonpickle.decode(f.read())
    try:
      print(f'Running {path.stem}')
      sim_result = Scenario(fuzz_input).run({'simulator': fuzz_input.config['compatible_simulators'][0],
                                       'render_spectator': False,
                                       'render_ego': False,
                                       'closedLoop': True,
                                       **config,
                                       }
                                      )
    except NonegoNonegoCollisionError as err:
      print(f'Collision between nonegos {err.nonego} and {err.other}.')
    except EgoCollisionError as err:
      print(f'Ego collided with {err.other}.')
    else:
      if sim_result:
        coverage_space = sim_result.records['coverage_space']
        coverage_sum.update(sim_result.records['coverage'])
      else:
        print(f'Simulation of {path} rejected!')
  return coverage_space, coverage_sum