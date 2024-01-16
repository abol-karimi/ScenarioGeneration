
#!/usr/bin/env python3.8

from scenariogen.core.coverages.coverage import Statement, StatementCoverage, StatementSetCoverage, Predicate, PredicateCoverage

p1 = Predicate('p')
p2 = Predicate('p')
s1 = Statement(p1, ('t',))
s2 = Statement(p2, ('t',))

print(p1 == p2)
print(s1 == s2)


