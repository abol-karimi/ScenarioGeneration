from clingo.ast import Transformer, parse_string
from scenariogen.core.coverages.coverage import PredicateCoverage

def time_to_term(seconds):
    return f't_seconds_{str(seconds).replace(".", "_")}'


def term_to_time(term):
    return float(term[10:].replace("_", "."))


def predicates_of_logic_program(program_str):
    predicates = PredicateCoverage([])
    class AtomNameRecorder(Transformer):
        def visit_SymbolicAtom(self, node):
            predicates.add(node.symbol.name)
            return node
    anr = AtomNameRecorder()
    parse_string(program_str, lambda stm: anr(stm))

    return predicates