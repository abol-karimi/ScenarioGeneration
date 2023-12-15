from scenic.domains.driving.roads import Network

from scenariogen.core.utils import classify_intersection
from scenariogen.predicates.utils import predicates_of_logic_program

def coverage_space(config):
  network = Network.fromFile(config['map'])
  traffic_rules_file = classify_intersection(network, config['intersection']) + '.lp'
  with open(f'src/scenariogen/predicates/{traffic_rules_file}', 'r') as f:
    encoding = f.read()
  
  predicate_coverage_space = predicates_of_logic_program(encoding)

  return predicate_coverage_space