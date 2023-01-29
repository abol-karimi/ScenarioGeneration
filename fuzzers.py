from dataclasses import dataclass
from typing import Dict, Any
import scenic

# This project


@dataclass
class ModularFuzzer:
  config : Dict
  coverage : Any # For both evaluation and seed generation purposes
  mutator : Any
  scheduler : Any

  def run(self, initial_seeds, iterations, render=False):
    seed = initial_seeds[0]
    for i in range(iterations):
      # Run the simulation with the current seed
      print(f'Simulating seed {i}')
      events = self.simulate(seed, render=render)

      # Compute the predicate coverage of the current seed
      predicates = self.coverage.compute(seed, events)
      print(predicates)

      # Add the seed and its predicate coverage to the scheduler
      self.scheduler.add(seed, predicates)

      # Choose a seed to mutate for the next iteration
      print(seed)
      seed = self.scheduler.choose()
      print(seed)
      seed = self.mutator.mutate(seed)

      for p in predicates:
          print(p)

    return None

  def simulate(self, seed, simulate_ego=False, render=False):
    # Run the scenario on the seed
    from intersection_monitor import Monitor
    event_monitor = Monitor()
    params = {'config': self.config,
            'event_monitor': event_monitor,
            'render': False,
            'seed': seed}
    scenic_scenario = scenic.scenarioFromFile(
        'nonegos.scenic', params=params)
    scene, _ = scenic_scenario.generate()
    simulator = scenic_scenario.getSimulator()
    if not render:
      settings = simulator.world.get_settings()
      settings.no_rendering_mode = True
      simulator.world.apply_settings(settings)
    sim_result = simulator.simulate(scene, maxSteps=self.config['maxSteps'])
    del scenic_scenario, scene

    return event_monitor.get_events()



