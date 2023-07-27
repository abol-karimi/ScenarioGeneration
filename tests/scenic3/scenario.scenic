""" Scenario Description
Som description.
"""

## SET MAP AND MODEL (i.e. definitions of all referenceable vehicle types, road library, etc)
param carla_map = 'Town05'
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{globalParameters.carla_map}.xodr'
param render = '0'
model scenic.simulators.newtonian.driving_model

scenario A():
  setup:
    car1 = new Car,
      with name 'car1',
      with behavior FollowLaneBehavior()
    car2 = new Car,
      with name 'car2',
      with behavior FollowLaneBehavior()
    cars = [car1, car2]

monitor RecordEventsMonitor(events, cars):
  for car in cars:
    events.append(f'{car.name} at time 0')
  wait

monitor Dummy():
  print(f'Dummy time: {simulation().currentTime}')
  wait

scenario RecordEventsScenario(cars):
  setup:
    events = []
    require monitor RecordEventsMonitor(events, cars)

a = A()
b = RecordEventsScenario(a.cars)
scenario Main():
  setup:
    car4 = new Car,
      with name 'car4',
      with behavior FollowLaneBehavior()
    require monitor Dummy()
    record final tuple(b.events) as events
  compose:
    do a, b
