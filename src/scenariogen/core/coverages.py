from collections import Counter
import clingo
from scenic.domains.driving.roads import Network

# This project
from scenariogen.core.utils import geometry_atoms


class PredicateNameCoverage:
 
  def __init__(self, predicates=set()):
    self.coverage = Counter(predicates)
  
  def __sub__(self, other):
     return self.coverage - other.coverage
  
  def __iadd__(self, other):
     self.coverage += other.coverage 

  def __len__(self):
    return len(self.coverage)
  
  def is_novel_to(self, other):
     return len(self.coverage.keys() - other.coverage.keys()) == 0
  
  @classmethod
  def from_sim(cls, sim_result):
    config = sim_result.records['config']
    events = sim_result.records['events']

    network = Network.fromFile(config['map'])
    atoms = []
    atoms += geometry_atoms(network,
                            config['intersection'])
    atoms += [str(e) for e in events]
    program = '.\n'.join(atoms)+'.\n'

    ctl = clingo.Control()
    ctl.load(f"src/scenariogen/predicates/{config['traffic_rules']}")
    ctl.add("base", [], program)
    ctl.ground([("base", [])])
    ctl.configuration.solve.models = "1"
    predicates = set()
    with ctl.solve(yield_=True) as handle:
        for model in handle:
            for atom in model.symbols(atoms=True):
                predicates.add(str(atom.name))
    return cls(predicates)
  
