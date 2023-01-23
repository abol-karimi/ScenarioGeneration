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

  def run(self, initial_seeds, num_steps, render=False):
    seed = initial_seeds[0]
    for i in range(num_steps):
      seed = self.mutator.mutate(seed)
      events = self.simulate(seed, render=render)
      self.scheduler.add(seed, events)
      seed = self.scheduler.choose()

      for e in events:
          print(e.withTime(e.frame))

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



