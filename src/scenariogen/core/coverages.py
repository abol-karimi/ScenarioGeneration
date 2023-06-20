from typing import Dict
from collections import Counter
from dataclasses import dataclass
import clingo
from scenic.domains.driving.roads import Network

# This project
from src.scenariogen.core.utils import geometry_atoms

@dataclass
class PredicateNameCoverage:
  config : Dict
  
  def __init__(self):
    self.coverage = Counter()
  
  def __sub__(self, other):
     return self.coverage - other.coverage
  
  def __iadd__(self, other):
     self.coverage += other.coverage 

  def __len__(self):
    return len(self.coverage)
  
  def is_novel_to(self, other):
     return len(self.coverage.keys() - other.coverage.keys())
  
  @classmethod
  def from_sim(cls, sim_result):
    events = sim_result.records['events']

    network = Network.fromFile(cls.config['map'])
    atoms = []
    atoms += geometry_atoms(network,
                            cls.config['intersection'])
    atoms += [str(e) for e in events]
    program = '.\n'.join(atoms)+'.\n'

    ctl = clingo.Control()
    ctl.load(cls.config['traffic_rules'])
    ctl.add("base", [], program)
    ctl.ground([("base", [])])
    ctl.configuration.solve.models = "1"
    predicates = set()
    with ctl.solve(yield_=True) as handle:
        for model in handle:
            for atom in model.symbols(atoms=True):
                predicates.add(str(atom.name))
    return cls(predicates)
  
