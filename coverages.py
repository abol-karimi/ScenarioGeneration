from typing import Dict
from dataclasses import dataclass
import clingo
from scenic.domains.driving.roads import Network

# This project
from utils import geometry_atoms

@dataclass
class PredicateNameCoverage:
  config : Dict

  def compute(self, seed, events):
    network = Network.fromFile(self.config['map'])
    atoms = []
    atoms += geometry_atoms(network,
                            self.config['intersection'])
    atoms += [str(e) for e in events]
    program = '.\n'.join(atoms)+'.\n'

    ctl = clingo.Control()
    ctl.load(self.config['traffic_rules'])
    ctl.add("base", [], program)
    ctl.ground([("base", [])])
    ctl.configuration.solve.models = "1"
    predicates = set()
    with ctl.solve(yield_=True) as handle:
        for model in handle:
            for atom in model.symbols(atoms=True):
                predicates.add(str(atom.name))

    return predicates