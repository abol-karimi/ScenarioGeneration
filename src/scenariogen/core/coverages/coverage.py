from pathlib import Path
import jsonpickle

from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoCollisionError

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
    except NonegoCollisionError as err:
      print(f'Collision between nonegos {err.nonego} and {err.other}.')
    except EgoCollisionError as err:
      print(f'Ego collided with {err.other}.')
    else:
      if sim_result:
        coverage_sum += sim_result.records['coverage']
      else:
        print(f'Simulation of {path} rejected!')
  return coverage_sum


class PredicateCoverage:
  """
  Coverage of predicates, ignoring the values of their arguments.
  TODO make it a subclass of abc
  """

  def __init__(self, predicates=set()) -> None:
    self.predicates = predicates
  
  def add(self, pred):
    self.predicates.add(pred)

  def __iadd__(self, other):
    self.predicates.update(other.predicates)
  
  def update(self, other):
    self += other
    
  def __sub__(self, other):
    return self.predicates - other.predicates

  def __len__(self):
    return len(self.predicates)
  
  def is_novel_to(self, other):
    return len(self - other) > 0

  def print(self):
    print('Predicate coverage:')
    for pred in self.predicates:
      print(pred)


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
  
  def is_novel_to(self, other):
    return len(self - other) > 0

  def print(self):
    print('Statement coverage:')
    for pred_name in self.pred2args:
        print(f'{pred_name}:')
        for pred_args in self.pred2args[pred_name]:
            print(f'\t{pred_args}')