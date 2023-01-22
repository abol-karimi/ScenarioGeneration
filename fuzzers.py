from dataclasses import dataclass
from typing import Dict
import scenic

# This project
from mutators import RandomMutator
from schedulers import RandomScheduler

@dataclass
class RandomFuzzer:
  config : Dict
  mutator : RandomMutator
  scheduler : RandomScheduler

  def run(self, initial_seeds, num_steps):
    config = self.config
    from intersection_monitor import Monitor

    seed = initial_seeds[0]
    for i in range(num_steps):
      seed = self.mutator.mutate(seed)

      # Run the scenario on the seed
      event_monitor = Monitor()
      params = {'config': config,
              'event_monitor': event_monitor,
              'render': False,
              'seed': seed}
      scenic_scenario = scenic.scenarioFromFile(
          'nonegos.scenic', params=params)
      scene, _ = scenic_scenario.generate()
      simulator = scenic_scenario.getSimulator()
      # settings = simulator.world.get_settings()
      # settings.no_rendering_mode = True
      # simulator.world.apply_settings(settings)
      sim_result = simulator.simulate(scene, maxSteps=config['maxSteps'])

      for events in event_monitor.events.values():
        for e in events:
            print(e.withTime(e.frame))
      


    return None