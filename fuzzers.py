from dataclasses import dataclass
from typing import Dict
import scenic

@dataclass
class RandomFuzzer:
  config : Dict

  def run(self, initial_seeds, num_steps):
    config = self.config
    from intersection_monitor import Monitor
    event_monitor = Monitor()

    params = {'config': config,
            'event_monitor': event_monitor,
            'render': False,
            'seed': initial_seeds[0]}

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