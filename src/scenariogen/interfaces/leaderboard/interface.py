from __future__ import print_function

import traceback
import importlib
import os
import carla

from srunner.scenariomanager.carla_data_provider import CarlaDataProvider
from srunner.scenariomanager.timer import GameTime

from leaderboard.autoagents.agent_wrapper import AgentWrapperFactory, validate_sensor_configuration
from leaderboard.utils.route_manipulation import interpolate_trajectory

sensors_to_icons = {
    'sensor.camera.rgb':        'carla_camera',
    'sensor.lidar.ray_cast':    'carla_lidar',
    'sensor.other.radar':       'carla_radar',
    'sensor.other.gnss':        'carla_gnss',
    'sensor.other.imu':         'carla_imu',
    'sensor.opendrive_map':     'carla_opendrive_map',
    'sensor.speedometer':       'carla_speedometer'
}

class LeaderboardAgent(object):
    """
    Main class of the Leaderboard. Everything is handled from here,
    from parsing the given files, to preparing the simulation, to running the route.
    """

    def __init__(self, args):
        """
        Setup CARLA client and world
        Setup ScenarioManager
        """
        self.client = args.client
        self.world = args.world

        # Load agent
        module_name = os.path.basename(args.agent).split('.')[0]
        self.module_agent = importlib.import_module(module_name)

        #-----------------------------------------------------------------------------------------
        CarlaDataProvider.set_client(self.client)
        CarlaDataProvider.set_world(self.world) # Who uses CarlaData provider?
        self.world.tick()

        # Set up the user's agent
        agent_class_name = getattr(self.module_agent, 'get_entry_point')()
        agent_class = getattr(self.module_agent, agent_class_name)
        self.agent_instance = agent_class(args.host, args.port, args.debug)
        self.agent_instance.set_global_plan(args.gps_route, args.route)
        self.agent_instance.setup(args.agent_config)

        # Check and store the sensors
        self.sensors = self.agent_instance.sensors()
        track = self.agent_instance.track
        validate_sensor_configuration(self.sensors, track, args.track)
        self.sensor_icons = [sensors_to_icons[sensor['type']] for sensor in self.sensors]

        self._agent_wrapper = AgentWrapperFactory.get_wrapper(self.agent_instance)
        self._agent_wrapper.setup_sensors(args.carla_actor)

        self.world.on_tick(self.on_scenic_tick)

    def _cleanup(self):
        """
        Remove and destroy all actors
        """
        CarlaDataProvider.cleanup()

        try:
            if self.agent_instance:
                self.agent_instance.destroy()
                self.agent_instance = None
        except Exception as e:
            print("\n\033[91mFailed to stop the agent:")
            print(f"\n{traceback.format_exc()}\033[0m")

        if self.route_scenario:
            self.route_scenario.remove_all_actors()
            self.route_scenario = None

        # Make sure no sensors are left streaming
        alive_sensors = self.world.get_actors().filter('*sensor*')
        for sensor in alive_sensors:
            sensor.stop()
            sensor.destroy()


    def run_step(self):
        vehicle_control = self._agent_wrapper()
        return vehicle_control
    
    def on_scenic_tick(self, timestamp):
        GameTime.on_carla_tick(timestamp)
        CarlaDataProvider.on_carla_tick()


