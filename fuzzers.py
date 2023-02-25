from dataclasses import dataclass
from typing import Dict, Any, Set
import scenic
import time
from scenic.simulators.newtonian import NewtonianSimulator

# This project


@dataclass
class ModularFuzzer:
  config : Dict
  coverage : Any # For both evaluation and seed generation purposes
  mutator : Any
  scheduler : Any
  seed_corpus : Any
  predicate_coverage = set()

  def run(self, iterations, render=False):
    for seed in self.seed_corpus.seeds:
      events = self.simulate(seed, render=render)
      predicates = self.coverage.compute(seed, events)
      self.scheduler.add(seed, predicates)

    for i in range(iterations):
      print('-'*20 + f'Iteration {i}' + '-'*20)
      seed = self.mutator.mutate(self.scheduler.choose())
      try:
        events = self.simulate(seed, render=render)
      except Exception as err:
        print(err)
        # TODO if two nonegos collide, discard seed
        # else if the ego collides with the mutant, add seed to corpus
        continue
      predicates, is_novel = self.compute_coverage(seed, events)
      self.scheduler.add(seed, predicates)
      if is_novel:
        self.seed_corpus.add(seed)
        self.predicate_coverage.update(predicates)

    return self.seed_corpus

  def simulate(self, seed, simulate_ego=False, render=False):
    print(f'Simulating the seed...')

    # Run the scenario on the seed
    from intersection_monitor import Monitor
    event_monitor = Monitor()
    params = {'config': self.config,
            'event_monitor': event_monitor,
            'render': False,
            'seed': seed}

    start_time = time.time()
    scenic_scenario = scenic.scenarioFromFile(
        'nonegos_newtonian.scenic', 
        params=params, 
        model='scenic.simulators.newtonian.driving_model')
    print(f'Compilation took {round(time.time()-start_time, 3)} seconds.')

    scene, _ = scenic_scenario.generate(maxIterations=1)
    simulator = NewtonianSimulator()

    start_time = time.time()
    sim_result = simulator.simulate(
                    scene,
                    maxSteps=self.config['maxSteps'],
                    maxIterations=1,
                    raiseGuardViolations=True
                    )
    print(f'Simulation took {round(time.time()-start_time, 3)} seconds.')

    del scenic_scenario, scene

    return event_monitor.get_events()

  def compute_coverage(self, seed, events):
    predicates = self.coverage.compute(seed, events)
    is_novel = (0 == len(predicates - self.predicate_coverage))
    return predicates, is_novel
    




