#!/usr/bin/env python3.8
from scenariogen.core.errors import EgoCollisionError, InvalidSeedError

try:
    sim_result = Scenario(seed).run()
  except InvalidSeedError:
      print('Invalid seed, discarding it.')
  except EgoCollisionError:
      print('Ego collision. Saving the seed to corpus...')
      with open(f'experiments/predicate-coverage/corpus_atheris/{iteration}.json', 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))