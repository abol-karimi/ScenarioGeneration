""" Scenario Description
Replay complexgen's scenario without the ego agents ('ego' and 'illega').
"""
param map = localPath('/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/Town05.xodr')  # or other CARLA map that definitely works
param carla_map = 'Town05'
model scenic.simulators.carla.model

import jsonpickle
param complexgen_scenario_path = None
with open(globalParameters.caller_config['complexgen_scenario_path'], 'r') as f:
  scenario = jsonpickle.decode(f.read())
param timestep = scenario.timestep
param steps = scenario.maxSteps

intersection = network.elements[scenario.intersection_uid]
blueprints = scenario.blueprints
events = scenario.events
curves = scenario.curves
sim_trajs = scenario.sim_trajectories
sample_size = int(scenario.maxSteps)+1

from complexgen.core.utils import curves_to_trajectories
trajectory = curves_to_trajectories(curves, sim_trajs, sample_size)

from scenariogen.core.geometry import CurvilinearTransform
ego_lanes = tuple(network.elements[uid] for uid in scenario.maneuver_uid['ego'])
ego_route = tuple(l.uid for l in ego_lanes)
ego_p0 = trajectory['ego'][0][0]
transform = CurvilinearTransform([p for lane in ego_lanes
                                    for p in lane.centerline.lineString.coords
                                    ])
ego_init_progress_x = transform.curvilinear(ego_p0)[0]

config = {'description': 'A scenario imported from complexgen',
          'carla-map': scenario.map_name,
          'map': scenario.map_path,
          'weather': scenario.weather,
          'timestep': scenario.timestep,
          'steps': globalParameters.steps,
          'intersection': scenario.intersection_uid,
          'ego_blueprint': scenario.blueprints['ego'],
          'ego_route': ego_route,
          'ego_init_progress_ratio': ego_init_progress_x/transform.axis.length,
          }

import complexgen.simulators.carla.visualization as visualization
from complexgen.core.signals import SignalType

car2time2signal = {car:{e.frame:e.signal for e in es if e.name == 'signaledAtForkAtTime'} 
	for car, es in events.items()}

behavior ReplayBehavior():
	carla_world = simulation().world
	while True:
		t = simulation().currentTime
		state = trajectory[self.name][t]
		take SetPoseAction(state[0], state[1])

		if car2time2signal[self.name].__contains__(t):
			lights = SignalType[car2time2signal[self.name][t].upper()].to_vehicleLightState()
			take SetVehicleLightStateAction(lights)

		visualization.label_car(carla_world, self)

scenario SeedScenario():
  setup:
    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
      blueprint_lib = jsonpickle.decode(f.read())

    for carName, traj in trajectory.items():
      if carName in {'ego', 'illegal'}:
        continue
      carState = traj[0]
      car = new Car at carState[0], facing carState[1],
        with name carName,
        with blueprint blueprints[carName],
        with length blueprint_lib[blueprints[carName]]['length'],
        with width blueprint_lib[blueprints[carName]]['width'],
        with color Color(0, 0, 1),
        with route scenario.maneuver_uid[carName],
        with physics False,
        with allowCollisions False,
        with behavior ReplayBehavior()
