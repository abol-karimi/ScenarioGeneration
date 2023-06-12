from dataclasses import dataclass
from typing import Dict, Any, Set
import scenic
import time
from scenic.simulators.newtonian import NewtonianSimulator

# This project
import seed_corpus

@dataclass
class ModularFuzzer:
  config : Dict
  coverage : Any # For both evaluation and seed generation purposes
  mutator : Any
  scheduler : Any
  corpus : Any
  predicate_coverage = set()

  def run(self):
    start_time = time.time()

    for seed in self.corpus.seeds:
      events = self.simulate(seed)
      predicates = self.coverage.compute(seed, events)
      self.scheduler.add(seed, predicates)

    for i in range(self.config['iterations']):
      print(f'Total elapsed time: {round(time.time()-start_time, 3)} seconds.')
      print('-'*20 + f'Starting iteration {i+1}/{self.config["iterations"]}' + '-'*20)
      seed = self.mutator.mutate(self.scheduler.choose())
      try:
        events = self.simulate(seed)
      except Exception as err: # TODO non-ego nonego collision
        # if two nonegos collide, discard the seed:
        print('\tInvalid mutant, discarding it:')
        print(f'\t{err}')
      # TODO
      # except EgoCollision:
      #   classify: ego's fault, or non-ego's fault
      #   add seed to corpus if ego's fault
        continue
      predicates, is_novel = self.compute_coverage(seed, events)
      self.scheduler.add(seed, predicates)
      if True: #is_novel:
        self.corpus.add(seed)
        self.predicate_coverage.update(predicates)

    return self.corpus

  def simulate(self, seed):
    """ Runs the scenario on the given seed.
    Returns the discrete-time trajectories.
    """
    # Sample the nonego splines.
    seconds = seed.trajectories[0].ctrlpts[-1][2]
    
    # For closed-loop fuzzing, simulate the ego too.
    params = {'carla_map': self.corpus.config['carla_map'],
              'map': self.corpus.config['map'],
              'render': True,
              'timestep': self.config['timestep'],
              'config': {'seed': seed, **self.config},
              }

    scenic_scenario = scenic.scenarioFromFile(
                        'run_seed.scenic',
                        scenario='ClosedLoop' if self.config['ego'] else 'OpenLoop',
                        params=params)
    print(f'Initializing the scenario...')
    scene, _ = scenic_scenario.generate(maxIterations=1)
    simulator = NewtonianSimulator()

    print(f'Simulating the scenario...')
    sim_result = simulator.simulate(
                    scene,
                    maxSteps=int(seconds / self.config['timestep']),
                    maxIterations=1,
                    raiseGuardViolations=True)
    events = sim_result.records['events']
    del scenic_scenario, scene
    return events

  def compute_coverage(self, seed, events):
    predicates = self.coverage.compute(seed, events)
    is_novel = (0 == len(predicates - self.predicate_coverage))
    return predicates, is_novel
    
  def save(self, out_corpus):
    self.corpus.save(out_corpus)



