import os
from functools import reduce
from pathlib import Path
import jsonpickle
from typing import Tuple

from scenic.core.simulators import SimulationCreationError

from scenariogen.core.fuzzing.runner import Runner
from scenariogen.core.errors import EgoCollisionError, NonegoCollisionError


class Predicate:
  def __init__(self, name: str):
    self.name = name

  def __eq__(self, other):
    return self.name == other.name
  
  def __str__(self):
    return self.name
   
  def __hash__(self) -> int:
    return hash(self.name)
   

class Statement:
  def __init__(self, predicate: Predicate, args: Tuple[str]):
    self.predicate = predicate
    self.args = args

  def __eq__(self, other):
    return self.predicate == other.predicate and self.args == other.args

  def __hash__(self) -> int:
    return hash((self.predicate, self.args))

  def cast_to(self, cls):
    if cls is Statement:
      return self
    elif cls is Predicate:
      return self.predicate
    else:
      assert False

  def __str__(self):
    return f"{self.predicate}({','.join(self.args)})" 


class Coverage:
  def __init__(self, items) -> None:
    self.items = frozenset(items)

  def __len__(self):
    return len(self.items)
  
  def __eq__(self, other):
    return self.items == other.items
  
  def __hash__(self):
    return hash(tuple(self.items))

  def __add__(self, other):
    return self.__class__(self.items.union(other.items))
    
  def __sub__(self, other):
    return self.__class__(self.items - other.items)
  
  def __and__(self, other):
    return self.__class__(self.items & other.items)

  def print(self):
    for item in self.items:
      if isinstance(item, Predicate) or isinstance(item, Statement):
        print(str(item))
      else:
        item.print()


class PredicateCoverage(Coverage):
  """
  Coverage of predicates, ignoring the values of their arguments.
  """
  def __init__(self, items):
    super().__init__(items)
    assert all(isinstance(item, Predicate) for item in items)
  
  def cast_to(self, cls):
    if cls is PredicateCoverage:
      return self
    else:
      assert False

  def print(self):
    for item in self.items:
      print(f'\t{item}')

  def __contains__(self, item):
    return isinstance(item, Predicate) and item in self.items


class PredicateSetCoverage(Coverage):
  """
  Coverage of sets of predicates.
  """
  def __init__(self, items):
    super().__init__(items)
    assert all(isinstance(item, PredicateCoverage) for item in items)
  
  def cast_to(self, cls):
    if cls is PredicateSetCoverage:
      return self
    elif cls is PredicateCoverage:
      return reduce(lambda x,y: x+y, self.items, PredicateCoverage([]))
    else:
      assert False

  def print(self):
    for i, cov in enumerate(self.items):
      print(f'{i}th predicate coverage:')
      cov.print()

  def __contains__(self, item):
    return isinstance(item, PredicateCoverage) and item in self.items


class StatementCoverage(Coverage):
  """
  Coverage of statements, i.e. considering predicates together with their argument values.
  """
  def __init__(self, items):
    super().__init__(items)
    assert all(isinstance(item, Statement) for item in items)
  
  def cast_to(self, cls):
    if cls is StatementCoverage:
      return self
    elif cls is PredicateCoverage:
      return PredicateCoverage(item.cast_to(Predicate) for item in self.items)
    else:
      assert False
  
  def filter(self, statement_filter):
    return StatementCoverage(filter(statement_filter, self.items))
  
  def print(self):
    for item in self.items:
      print(f'\t{item}')

  def __contains__(self, item):
    return isinstance(item, Statement) and item in self.items
    

class StatementSetCoverage(Coverage):
  """
  Coverage of sets of statements.
  """
  def __init__(self, items):
    super().__init__(items)
    assert all(isinstance(item, StatementCoverage) for item in items)
   
  def cast_to(self, cls):
    if cls is StatementSetCoverage:
      return self
    elif cls is StatementCoverage:
      return reduce(lambda x,y: x+y, self.items, StatementCoverage([]))
    elif cls is PredicateSetCoverage:
      return PredicateSetCoverage(cov.cast_to(PredicateCoverage) for cov in self.items)
    elif cls is PredicateCoverage:
      return self.cast_to(PredicateSetCoverage).cast_to(PredicateCoverage)
  
  def filter(self, statement_filter):
    return StatementSetCoverage(statement_cov.filter(statement_filter) for statement_cov in self.items)
  
  def print(self):
    print('Statement-set coverage:')
    for i, cov in enumerate(self.items):
      print(f'  {i}-th statement coverage:')
      cov.print()
  
  def __contains__(self, item):
    return isinstance(item, StatementCoverage) and item in self.items


def from_corpus(corpus_folder, config):
  input2coverage = {}
  nonego_collisions = set()
  ego_collisions = set()
  simulation_creation_errors = set()
  simulation_rejections = set()
  none_coverages = set()

  paths = list(Path(corpus_folder).glob('*'))
  paths.sort(key=lambda x: os.path.getmtime(x))
  for path in paths:
    with open(path, 'r') as f:
      fuzz_input = jsonpickle.decode(f.read())
    try:
      print(f'Running {path.name}')
      sim_result = Runner.run({'render-spectator': False,
                               'render-ego': False,
                               **config,
                               **fuzz_input.config,                               
                               'fuzz-input': fuzz_input,
                              })
    except NonegoCollisionError as err:
      nonego_collisions.add(path)
      print(f'Collision between {err.nonego} and {err.other}.')
    except EgoCollisionError as err:
      ego_collisions.add(path)
      print(f'Ego collided with {err.other}.')
    except SimulationCreationError as e:
      simulation_creation_errors.add(path)
      print(e)
    except Exception as e:
      print(e)
    else:
      if not sim_result:
        simulation_rejections.add(path)
        print(f'Simulation rejected!')
      elif sim_result.records['coverage'] is None:
        none_coverages.add(path)
        print(f'Simulation failed to report coverage!')
      else:
        input2coverage[path] = sim_result.records['coverage']

  return (input2coverage,
          nonego_collisions,
          ego_collisions,
          simulation_creation_errors,
          simulation_rejections,
          none_coverages)

