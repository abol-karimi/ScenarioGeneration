from clingo.ast import Transformer, parse_string
from scenariogen.core.coverages.coverage import PredicateCoverage

def time_to_term(seconds):
    return f't{str(seconds).replace(".", "_")}'


def term_to_time(term):
    return float(term[1:].replace("_", "."))


def predicates_of_logic_program(program_str, include_timed_predicates=False):
    predicates = PredicateCoverage([])
    class AtomNameRecorder(Transformer):
        def visit_SymbolicAtom(self, node):
            if include_timed_predicates or \
                (not node.symbol.name.endswith('AtTime') and \
                 not node.symbol.name == 'changedSignalBetween'):
                predicates.add(node.symbol.name)
            return node
    anr = AtomNameRecorder()
    parse_string(program_str, lambda stm: anr(stm))

    return predicates