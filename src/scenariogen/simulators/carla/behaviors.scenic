# Scenic parameters
model scenic.simulators.carla.model

param config = None
config = globalParameters.config

# imports
from collections import namedtuple
import carla
from leaderboard.envs.sensor_interface import SensorReceivedNoData

# from rss.rss_sensor import RssSensor
from agents.navigation.behavior_agent import BehaviorAgent
from scenic.simulators.carla.utils.utils import scenicToCarlaLocation, carlaToScenicPosition
from scenariogen.simulators.carla.utils import (signal_to_vehicleLightState, 
                                                maneuverType_to_Autopilot_turn,
                                                interpolate_trajectory
                                                )
import scenariogen.simulators.carla.visualization as visualization
from scenariogen.interfaces.leaderboard.agent import LeaderboardAgent


behavior AutopilotRouteBehavior(maneuver_types, config_override={}):
  defaults = {
    'auto_lane_change': Uniform(True, False),
    'distance_to_leading_vehicle': Range(1, 10), # i.e. minimum moving distance
    'ignore_lights_percentage': Range(0, 100),
    'ignore_signs_percentage': Range(0, 100),
    'random_left_lanechange_percentage': Range(0, 100),
    'random_right_lanechange_percentage': Range(0, 100),
    'update_vehicle_lights': Uniform(True, False),
  }
  config = {**defaults, **config_override}

  simulation().tm.auto_lane_change(self.carlaActor, config['auto_lane_change'])
  simulation().tm.distance_to_leading_vehicle(self.carlaActor, config['distance_to_leading_vehicle'])
  simulation().tm.ignore_lights_percentage(self.carlaActor, config['ignore_lights_percentage'])
  simulation().tm.ignore_signs_percentage(self.carlaActor, config['ignore_signs_percentage'])
  simulation().tm.random_left_lanechange_percentage(self.carlaActor, config['random_left_lanechange_percentage'])
  simulation().tm.random_right_lanechange_percentage(self.carlaActor, config['random_right_lanechange_percentage'])
  simulation().tm.update_vehicle_lights(self.carlaActor, config['update_vehicle_lights'])

  turns = [maneuverType_to_Autopilot_turn(m) for m in maneuver_types]
  simulation().tm.set_route(self.carlaActor, turns)
  take SetAutopilotAction(True)


behavior AutopilotPathBehavior(path):
  for p in path:
    visualization.draw_point(simulation().world, p, 1,
                              size=0.1,
                              color=carla.Color(255, 0, 0),
                              lifetime=120)

  print(f'Turning autopilot on for {self.name} at step {simulation().currentTime}...')
  # Use turn signals when turning:
  simulation().tm.update_vehicle_lights(self.carlaActor, True)
  # Follow traffic rules:
  simulation().tm.ignore_signs_percentage(self.carlaActor, 0)	
  # No lane changes as we are interested in behavior at intersections:
  simulation().tm.random_left_lanechange_percentage(self.carlaActor, 0)
  simulation().tm.random_right_lanechange_percentage(self.carlaActor, 0)
  simulation().tm.auto_lane_change(self.carlaActor, False)

  carla_path = [scenicToCarlaLocation(wp, world=simulation().world) for wp in path]
  simulation().tm.set_path(self.carlaActor, carla_path)
  take SetAutopilotAction(True)


behavior BehaviorAgentReachDestination(dest, aggressiveness='normal', debug=False):
  agent = BehaviorAgent(self.carlaActor,
                        behavior=aggressiveness,
                        map_inst=simulation().map)
  agent.set_destination(scenicToCarlaLocation(dest, world=simulation().world),
                        scenicToCarlaLocation(self.position, world=simulation().world))
  
  if debug:
    for wp, _ in agent._local_planner._waypoints_queue:
      visualization.draw_point(simulation().world,
                                carlaToScenicPosition(wp.transform.location),
                                None,
                                size=0.2,
                                color=carla.Color(255, 0, 0),
                                lifetime=60)
      
  while not agent.done():
    control = agent.run_step(debug=debug)
    self.carlaActor.apply_control(control)
    wait

  print(f'Car {self.name} reached its destination.')


behavior BehaviorAgentFollowWaypoints(waypoints, aggressiveness):
  agent = BehaviorAgent(self.carlaActor, behavior=aggressiveness)
  carla_world = simulation().world

  for wp in waypoints:
    agent.set_destination(scenicToCarlaLocation(wp, world=carla_world))
    while not agent.done():
      self.carlaActor.apply_control(agent.run_step())
      wait

  print(f'Car {self.name} reached its last waypoint.')

  take SetThrottleAction(0), SetBrakeAction(1), SetSteerAction(0)


behavior BehaviorAgentRSSFollowWaypoints(waypoints, aggressiveness):
  agent = BehaviorAgent(self.carlaActor, behavior=aggressiveness)
  carla_world = simulation().world

  # TODO


behavior LeaderboardAgentBehavior(agent_path, agent_config, track, keypoints, debug=False):
  Args = namedtuple('Args',
                    ['host',
                      'port',
                      'client',
                      'world',
                      'carla_actor',
                      'agent',
                      'agent_config',
                      'track',
                      'route',
                      'gps_route',
                      'debug',
                      'scenario_config'
                    ]
                  )
  keypoints_carla = tuple(scenicToCarlaLocation(kp, world=simulation().world) for kp in keypoints)
  gps_route, route = interpolate_trajectory(simulation().map, keypoints_carla)
  args = Args(host='127.0.0.1',
        port='2000',
        client=simulation().client,
        world=simulation().world,
        carla_actor=self.carlaActor,
        agent=agent_path,
        agent_config=agent_config,
        track=track,
        route=route,
        gps_route=gps_route,
        debug=debug,
        scenario_config=config
        )
  agent = LeaderboardAgent(args)

  globalParameters.cleanup_callbacks.put(agent.cleanup)
  
  while True:
    try:
      control = agent.run_step()
      self.carlaActor.apply_control(control)
    except SensorReceivedNoData:
      print(f'SensorReceivedNoData exception in Leaderboard behavior at step {simulation().currentTime}!')
    wait
