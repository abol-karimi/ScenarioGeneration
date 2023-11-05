import os
import copy
from functools import reduce
from pathlib import Path
import jsonpickle

from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoCollisionError
from scenic.core.simulators import SimulationCreationError

class PredicateCoverage:
  """
  Coverage of predicates, ignoring the values of their arguments.
  TODO make it a subclass of abc
  """

  def __init__(self, predicates) -> None:
    self.predicates = set(predicates)
  
  def add(self, pred):
    self.predicates.add(pred)

  def __iadd__(self, other):
    self.predicates.update(other.predicates)
  
  def update(self, other):
    self.predicates.update(other.predicates)
  
  def __add__(self, other):
    return PredicateCoverage(self.predicates.union(other.predicates))
    
  def __sub__(self, other):
    return PredicateCoverage(self.predicates-other.predicates)

  def __len__(self):
    return len(self.predicates)
  
  def __eq__(self, other):
    return self.predicates == other.predicates

  def __hash__(self):
    return hash(repr(self.predicates))

  def print(self):
    for pred in self.predicates:
      print(f'\t{pred}')


class PredicateSetCoverage:
  """
  Coverage of sets of predicates.
  """

  def __init__(self, predicateCoverages) -> None:
    self.predicateCoverages = set(cov for cov in predicateCoverages)
  
  def add(self, predCov):
    self.predicateCoverages.add(predCov)
  
  def __add__(self, other):
    return PredicateSetCoverage(self.predicateCoverages.union(other.predicateCoverages))

  def __iadd__(self, other):
    self.predicateCoverages.update(other.predicateCoverages)
  
  def update(self, other):
    self.predicateCoverages.update(other.predicateCoverages)
    
  def __sub__(self, other):
    return PredicateSetCoverage(self.predicateCoverages-other.predicateCoverages)

  def __len__(self):
    return len(self.predicateCoverages)
  
  def to_predicateCoverage(self):
    return reduce(lambda x,y: x+y, self.predicateCoverages)

  def print(self):
    for cov in self.predicateCoverages:
      cov.print()


class StatementCoverage:
  """
  Coverage of statements, i.e. considering predicates together with their argument values.
  """

  def __init__(self, pred2args) -> None:
    self.pred2args = {pred:args for pred,args in pred2args}
  
  def add(self, pred, args):
    if pred in self.pred2args:
      self.pred2args[pred].add(args)
    else:
      self.pred2args[pred] = {args}
  
  def __add__(self, other):
    pred2args = copy.copy(self.pred2args)
    for pred, args in other.pred2args.items():
      if pred in self.pred2args:
        pred2args[pred] = self.pred2args[pred].union(args)
      else:
        pred2args[pred] = args
    
    return StatementCoverage(pred2args.items())

  def __iadd__(self, other):
    for pred in other.pred2args:
      if pred in self.pred2args:
        self.pred2args[pred].update(other.pred2args[pred])
      else:
        self.pred2args.update({pred: other.pred2args[pred]})
  
  def update(self, other):
    self += other

  def __sub__(self, other):
    diff = {pred:self.pred2args[pred] - other.pred2args[pred]
            for pred in set(self.pred2args.keys()).intersection(set(other.pred2args.keys()))}
    return {key:val for key,val in diff.items() if len(val) > 0}

  def __len__(self):
    return sum(len(args) for args in self.pred2args.values())

  def to_predicateCoverage(self):
    return PredicateCoverage(self.pred2args.keys())
  
  def to_predicateSetCoverage(self):
    return PredicateSetCoverage((self.to_predicateCoverage(),))
    
  def print(self):
    for pred_name in self.pred2args:
      print(f'{pred_name}:')
      for pred_args in self.pred2args[pred_name]:
          print(f'\t{pred_args}')


def from_corpus(corpus_folder, config):
  input2coverage = {}

  for path in Path(corpus_folder).glob('*'):
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
    except SimulationCreationError as e:
      print(e)
    except Exception as e:
      print(e)
    else:
      if not sim_result:
        print(f'Simulation rejected!')
      elif sim_result.records['coverage'] is None:
        print(f'Simulation failed to report coverage!')
      else:
        input2coverage[path] = sim_result.records['coverage']

  return input2coverage
