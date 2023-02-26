from typing import Dict
from dataclasses import dataclass
import clingo

# This project
from utils import geometry_atoms

@dataclass
class PredicateNameCoverage:
  config : Dict

  def compute(self, seed, events):
    atoms = []
    atoms += geometry_atoms(self.config['network'], 
                            self.config['intersection_uid'])
    atoms += [f'{e.withTime(e.frame)}' for e in events]
    program = '.\n'.join(atoms)+'.\n'

    ctl = clingo.Control()
    ctl.load(self.config['rules_path'])
    ctl.add("base", [], program)
    ctl.ground([("base", [])])
    ctl.configuration.solve.models = "1"
    models = []
    predicates = set()
    with ctl.solve(yield_=True) as handle:
        for model in handle:
            for atom in model.symbols(atoms=True):
                predicates.add(str(atom.name))

    return predicates