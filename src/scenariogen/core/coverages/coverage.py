import os
from pathlib import Path
import jsonpickle

from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoCollisionError

class PredicateCoverage:
  """
  Coverage of predicates, ignoring the values of their arguments.
  TODO make it a subclass of abc
  """

  def __init__(self, items) -> None:
    self.predicates = set(items)
  
  def add(self, pred):
    self.predicates.add(pred)

  def __iadd__(self, other):
    self.predicates.update(other.predicates)
  
  def update(self, other):
    self.predicates.update(other.predicates)
    
  def __sub__(self, other):
    return PredicateCoverage(self.predicates-other.predicates)

  def __len__(self):
    return len(self.predicates)
  
  def print(self):
    print('Predicate coverage:')
    for pred in self.predicates:
      print(f'\t{pred}')


class StatementCoverage:
  """
  Coverage of statements, i.e. considering predicates together with their argument values.
  """

  def __init__(self) -> None:
    self.pred2args = {}
  
  def add(self, pred, args):
    if pred in self.pred2args:
      self.pred2args[pred].add(args)
    else:
      self.pred2args[pred] = {args}
   
  def __iadd__(self, other):
    for pred in other.pred2args:
      if pred in self.pred2args:
        self.pred2args[pred].update(other.pred2args[pred])
      else:
        self.pred2args.update({pred: other.pred2args[pred]})
  
  def update(self, other):
    self += other

  def __sub__(self, other):
    return {pred:self.pred2args[pred] - other.pred2args[pred]
            for pred in set(self.pred2args.keys()).intersection(set(other.pred2args.keys()))}

  def __len__(self):
    return sum(len(args) for args in self.pred2args.values())
  
  def print(self):
    print('Statement coverage:')
    for pred_name in self.pred2args:
        print(f'{pred_name}:')
        for pred_args in self.pred2args[pred_name]:
            print(f'\t{pred_args}')


def from_corpus(corpus_folder, config):
  coverage_sum = None
  pathlist = list(Path(corpus_folder).glob('*.json'))
  pathlist_sorted = sorted(pathlist, key=os.path.getctime)

  for path in pathlist_sorted:
    with open(path, 'r') as f:
      fuzz_input = jsonpickle.decode(f.read())
    try:
      print(f'Running {path.name}')
      sim_result = Scenario(fuzz_input).run({'render_spectator': False,
                                             'render_ego': False,
                                             'closedLoop': True,
                                             **config,
                                             }
                                            )
    except NonegoCollisionError as err:
      print(f'Collision between {err.nonego} and {err.other}.')
    except EgoCollisionError as err:
      print(f'Ego collided with {err.other}.')
    else:
      if not sim_result:
        print(f'Simulation rejected!')
      elif sim_result.records['coverage'] is None:
        print(f'Simulation failed to report coverage!')
      elif coverage_sum is None:
        coverage_sum = type(sim_result.records['coverage'])([])
        coverage_sum.update(sim_result.records['coverage'])
      else:
        coverage_sum.update(sim_result.records['coverage'])

  return coverage_sum
