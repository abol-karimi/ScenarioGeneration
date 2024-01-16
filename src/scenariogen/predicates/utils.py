from clingo.ast import Transformer, parse_string
from scenariogen.core.coverages.coverage import Predicate

def time_to_term(seconds):
    return f't_seconds_{str(seconds).replace(".", "_")}'


def term_to_time(term):
    return float(term[10:].replace("_", "."))


def predicates_of_logic_program(program_str):
    predicates = []
    class AtomNameRecorder(Transformer):
        def visit_SymbolicAtom(self, node):
            predicates.append(Predicate(node.symbol.name))
            return node
        def visit_External(self, node):
            predicates.append(Predicate(node.atom.symbol.name))
            return node
    anr = AtomNameRecorder()
    parse_string(program_str, lambda stm: anr(stm))

    return predicates


