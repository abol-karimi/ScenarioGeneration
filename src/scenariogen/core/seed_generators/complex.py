from collections import OrderedDict
from itertools import product
import math
from pysmt.logics import QF_NRA
from pysmt.shortcuts import get_env, Solver, get_model, Symbol, Equals, And, Real
from pysmt.typing import REAL
import pysmt
import fractions
import clingo
import scenic
from scenic.domains.driving.roads import Network
from scenic.core.simulators import SimulationCreationError
from scenic.core.dynamics import GuardViolation

from src.scenariogen.predicates.events import StoppedAtForkEvent
from scenariogen.core.errors import (NoASPSolutionError,
                                     NoSMTSolutionError, 
                                     EgoCollisionError, 
                                     NonegoCollisionError)
from scenariogen.core.utils import (geometry_atoms,
                                    seed_from_sim)
from scenariogen.core.signals import SignalType

solver_name = "z3-binary"
path = ["z3", "-in", "-smt2"]
logics = [QF_NRA]
env = get_env()
env.factory.add_generic_solver(solver_name, path, logics)

def numeral_to_fp(num):
    if isinstance(num, fractions.Fraction):
        return num.numerator/num.denominator
    elif isinstance(num, pysmt.constants.Numeral):
        rat = num.approx()
        fr = rat.as_fraction()
        return fr.numerator/fr.denominator
    else:
        print('Incompatible type: ', num, type(num))
        return None


# Rounds r >=0 down to precision number of decimal places.
def round_up(r, precision=3):
    coeff = 10**precision
    return fractions.Fraction(math.ceil(r*coeff), coeff)


# Rounds r >=0 down to precision number of decimal places.
def round_down(r, precision=3):
    coeff = 10**precision
    return fractions.Fraction(math.floor(r*coeff), coeff)


# Returns sign(r)*round_up(abs(r), precision)
def round_norm_up(r, precision=3):
    if r >= 0:
        return round_up(r, precision)
    else:
        return -round_up(-r, precision)


# Returns sign(r)*round_down(abs(r), precision)
def round_norm_down(r, precision=3):
    if r >= 0:
        return round_down(r, precision)
    else:
        return -round_down(-r, precision)


def realtime_to_frame(t, timestep):
    return int(realtime_to_frame_float(t, timestep))


def realtime_to_frame_float(t, timestep):
    return t/timestep


def frame_to_realtime(frame, timestep):
    return frame*timestep


def distance_to_time(t, d, d_val):
    """t, d: array of coordinates of the control points of the composite Bezier curve.
    d_val: the d-value to at which the curve is projected to the t-axis.
    returns the projection.
    """
    i = 0
    while d[3*i+3] < d_val:
        i += 1
    # When here, d[3*i] <= d_val <= d[3*i+3]
    if d_val == d[3*i]:
        return t[i]
    elif d_val == d[3*i+3]:
        return t[i+1]

    # TODO use a numerical solver
    t_var = Symbol('t', REAL)
    b0 = (1-t_var)*(1-t_var)*(1-t_var)
    b1 = 3*t_var*(1-t_var)*(1-t_var)
    b2 = 3*t_var*t_var*(1-t_var)
    b3 = t_var*t_var*t_var

    constraints = [t_var > 0,
                   t_var < 1,
                   Equals(Real(d_val), d[3*i]*b0 + d[3*i+1]*b1 + d[3*i+2]*b2 + d[3*i+3]*b3)]

    t_global = None
    with Solver(name=solver_name, logic=QF_NRA):
        m = get_model(And(constraints))
        numeral = m.get_py_value(t_var)
        t_local = numeral_to_fp(numeral)
        t_global = (1-t_local)*t[i] + t_local*t[i+1]

    return t_global


def realtime_logicalTime_axioms():
    atoms = []

    # If perceptibly less-than, then realtime strictly less-than
    atoms += [f'realLTE(S, T) :- lessThan(S, T)',
              f':- lessThan(S, T), realLTE(T, S)']
    # If perceptibly equal, then realtime equal
    atoms += [f'realLTE(S, T) :- equal(S, T)',
              f'realLTE(T, S) :- equal(S, T)']
    # Internal consistency of perceptible order
    atoms += [f':- lessThan(S, T), equal(S, T)']
    atoms += [f':- lessThan(S, T), equal(T, S)']

    # realLTE is a partial order
    atoms += [f'realLTE(T1, T3) :- realLTE(T1, T2), realLTE(T2, T3)',
              f':- realLTE(T1, T2), realLTE(T2, T1), T1 != T2, not equal(T1, T2), not equal(T2, T1)']

    return atoms


def car_to_time_to_events(car2events):
    """Assumes that for each car, its events in car2events are given in nondecreasing time order.
    Each car is mapped to a time2events dictionary.
    For each distinct frame in the frames of events of a car, a distince time constant is chosen.
    Each time constant is mapped to the list of corresponding events.
    """
    from collections import OrderedDict
    car2time2events = {car: OrderedDict() for car in car2events.keys()}

    for car, events in car2events.items():
        last_frame = -1
        i = -1
        for e in events:
            if e.frame != last_frame:
                i += 1
                t = f't_{car}_{i}'
                car2time2events[car][t] = [e]
                last_frame = e.frame
            else:
                car2time2events[car][t] += [e]

    return car2time2events


def logical_solution(scenario, config, sim_events):
    """ Given the events for ego, nonego, and illegal (in 'sim_events')
    and their distances along the corresponding car's trajectory (in 'frame2distance_*'),
    find a timing for the events that satisfies the logical constraints.
    """

    atoms = []
    atoms += config['constraints']

    # TODO store geometry atoms in the scenario to avoid computing them each time.
    network = Network.fromFile(scenario.map_path)
    atoms += geometry_atoms(network, scenario.intersection_uid)

    atoms += realtime_logicalTime_axioms()

    # Atoms of all events
    all_events = {car: events for car, events in scenario.events.items()}
    all_events.update(sim_events)
    car2time2events = car_to_time_to_events(all_events)
    for car, time2events in car2time2events.items():
        for t, events in time2events.items():
            atoms += [f'{e.withTime(t)}' for e in events]
    # For each car, a total order on its events
    for time2events in car2time2events.values():
        t = list(time2events.keys())
        for i in range(len(t)-1):
            atoms += [f'realLTE({t[i]}, {t[i+1]})',
                      f':- realLTE({t[i+1]}, {t[i]})']
    # The order of events of existing nonegos
    old_nonegos = {car for car in scenario.events if not car in {
        'ego', 'illegal'}}
    sym2val = {t: events[0].frame
               for car in old_nonegos for t, events in car2time2events[car].items()}
    min_perceptible_time = 10  # frames
    atoms += [f'#script(python)\n'
              f'import clingo\n'
              f'sym2val = {sym2val}\n'
              f'def lessThan(S, T):\n'
              f'  lt = sym2val[S.name] + {min_perceptible_time} < sym2val[T.name]\n'
              f'  return clingo.Number(1) if lt else clingo.Number(0)\n'
              f'def equal(S, T):\n'
              f'  eq = abs(sym2val[S.name] - sym2val[T.name]) < {min_perceptible_time}\n'
              f'  return clingo.Number(1) if eq else clingo.Number(0)\n'
              f'#end']
    for s in sym2val:
        for t in sym2val:
            atoms += [f':- lessThan({s}, {t}), 0 = @lessThan({s}, {t})',
                      f':- equal({s}, {t}), 0 = @equal({s}, {t})']

    # Evidence that the new scenario has a solution
    atoms += [f':- V != illegal, violatesRightOf(ego, V)']
    atoms += [f':- violatesRule(ego, _)']

    # Evidence that the new scenario is strictly harder
    new_nonegos = [car for car in sim_events if not car in {'ego', 'illegal'}]
    atoms += [':- ' +
              ', '.join(f'not violatesRightOf(illegal, {car})' for car in new_nonegos)]
    atoms += [f':- violatesRule(illegal, _)']
    for nonego in old_nonegos:
        atoms += [f':- violatesRightOf(illegal, {nonego})']

    # To generate unique time constants:
    atoms += [f'#script(python)\n'
              f'import clingo\n'
              f'def time(V, Pred, Tm, TM):\n'
              f'  t = V.name + Pred.name + Tm.name + TM.name\n'
              f'  return clingo.Function(t, [])\n'
              f'#end']

    # The event StopppedAtForkAtTime is generated for new cars,
    #  based on the status of traffic rules violations:
    for car in new_nonegos+['ego', 'illegal']:
        atoms += [f'#count {{0:stoppedAtForkAtTime({car}, F, @time({car}, stop, T1, T2)); 1:lessThan(T1, @time({car}, stop, T1, T2)); 2:lessThan(@time({car}, stop, T1, T2),  T2) }} = 3 :-'
                  f'arrivedAtForkAtTime({car}, F, T1),'
                  f'hasStopSign(F),'
                  f'enteredForkAtTime({car}, F, T2),'
                  f'not violatesRule({car}, stopAtSign)']

    program = ""
    for atom in atoms:
        program += f'{atom}.\n'

    ctl = clingo.Control()
    ctl.load(scenario.rules_path)
    ctl.add("base", [], program)
    ctl.ground([("base", [])])
    ctl.configuration.solve.models = "10000"
    models = []
    with ctl.solve(yield_=True) as handle:
        for model in handle:
            models.append(model.symbols(atoms=True))

    print(f'Number of ASP models found: {len(models)}')

    return models, car2time2events


def model_to_constraints(model, car2time2events, old_nonegos):

    # Extract temporal constraints and the new events
    order_names = {'realLTE', 'lessThan', 'equal'}
    constraints = {n: set() for n in order_names}
    constraints['stop'] = set()

    for atom in model:
        name = str(atom.name)
        if name in order_names:
            args = [str(a) for a in atom.arguments]
            constraints[name].add((args[0], args[1]))
        # Events that are generated by the solver
        if name == 'stoppedAtForkAtTime':
            car, fork, time = tuple([str(a) for a in atom.arguments])
            if not car in old_nonegos:
                constraints['stop'].add(time)
                if time in car2time2events[car]:
                    car2time2events[car][time].append(
                        StoppedAtForkEvent(car, fork, None))
                else:
                    car2time2events[car][time] = [
                        StoppedAtForkEvent(car, fork, None)]

    # Sort the events by their realtime
    from functools import cmp_to_key

    def compare(s, t):
        LTE = constraints['realLTE']  # A total order for any fixed car
        lte, gte = (s, t) in LTE, (t, s) in LTE
        if lte and gte:
            return 0
        elif lte and not gte:
            return -1
        else:
            return 1
    for car, time2events in car2time2events.items():
        times = list(time2events.keys())
        times.sort(key=cmp_to_key(compare))
        car2time2events[car] = OrderedDict(
            [(t, time2events[t]) for t in times])

    return constraints, car2time2events


def smooth_trajectories(scenario, config,
                        sim_trajectories,
                        temporal_constraints,
                        car2time2events):
    """ Find:
    1. A realtime for each (ego, illegal, nonego) event distance s.t.
      (a) for each new agent, realtime is an increasing function of distance (no backing or teleportation)
      (b) the relative order of ruletimes of all events are preserved
    2. Cubic bezier interpolation between any two points (ts, ds) and (te, de)
      where ds, de are distances of two consecutive events of a car,
      and ts, te are the corresponding realtimes,
      and (ts+(te-ts)/3, d1) and (ts+2(te-ts)/3, d2) are intermediate control points, such that:
      (a) interpolation does not create new events
      (b) speed is continuous (to model no impact)
      (c) speed is small at stop events
      (d) bounds on speed
    """
    car2frame2simDistance = {car: frame_to_distance(sim_trajectories[car])
                             for car in sim_trajectories}

    new_cars = list(sim_trajectories.keys())

    t_dom = set()
    for s, t in temporal_constraints['lessThan']:
        t_dom.update({s, t})
    for s, t in temporal_constraints['equal']:
        t_dom.update({s, t})
    t_dom.update(temporal_constraints['stop'])

    time2distance = {}
    for car in new_cars:
        for t, events in car2time2events[car].items():
            if t in t_dom:
                f = events[0].frame
                time2distance[t] = car2frame2simDistance[car][f] if f != None else None

    car2distances = {car: [time2distance[t] for t in car2time2events[car] if t in t_dom]
                     for car in new_cars}

    maxTime = scenario.maxSteps*scenario.timestep
    t_list = {}
    for car in new_cars:
        var_list = [Symbol(t, REAL)
                    for t in car2time2events[car] if t in t_dom]
        t_list[car] = [Real(0)] + var_list + [Real(maxTime)]

    d_list = {}
    for car in new_cars:
        d_list[car] = [0 for i in range(len(t_list[car])*3-2)]
        d_list[car][0] = Real(0)
        d_list[car][-1] = Real(round_down(car2frame2simDistance[car][-1]))
        for i in range(1, len(d_list[car])-1):
            if i % 3 == 0:  # Interpolation point
                di = car2distances[car][i//3-1]
                if di == None:  # no distance constraint for this event
                    d_list[car][i] = Symbol(f'D_{car}_{i//3}', REAL)
                else:
                    d_list[car][i] = Real(round_down(di))
            else:  # Bezier control point
                d_list[car][i] = Symbol(f'D_{car}_{i//3}_{i%3}', REAL)

    # Index realtime variables by their name
    old_nonegos = {car for car in scenario.events if not car in {
        'ego', 'illegal'}}
    t2var = {}
    for ts in t_list.values():
        t2var.update({str(t): t for t in ts[1:-1]})
    t2var.update({t: Real(round_down(frame_to_realtime(events[0].frame, scenario.timestep)))
                  for car in old_nonegos for t, events in car2time2events[car].items() if t in t_dom})

    # Add extra control points to increase the flexibility of the curve
    max_separation = 30.
    t_list_augmented = {}
    d_list_augmented = {}
    for car in new_cars:
        t_list_augmented[car] = []
        d_list_augmented[car] = []
        for i in range(len(t_list[car])-1):
            ti = t_list[car][i]
            di, di_0, di_1, dii = d_list[car][3*i:3*i+4]

            t_list_augmented[car] += [ti]
            d_list_augmented[car] += [di, di_0, di_1]

            if not (di.is_constant() and dii.is_constant()):
                continue

            di_fp = numeral_to_fp(di.constant_value())
            dii_fp = numeral_to_fp(dii.constant_value())
            if dii_fp-di_fp <= max_separation:
                continue
            n = math.ceil((dii_fp-di_fp)/max_separation)
            separation = (dii_fp-di_fp)/n
            t_base = f'{car}_{ti}' if ti.is_constant() else ti
            t_list_augmented[car] += [Symbol(f'{t_base}_aug_{j}', REAL)
                                      for j in range(n-1)]
            for j in range(3*(n-1)):
                if j % 3 == 0:
                    d_list_augmented[car] += [
                        Real(round_down(di_fp+(j//3+1)*separation))]
                else:
                    d_list_augmented[car] += [
                        Symbol(f'D_{car}_{i}_aug_{j}', REAL)]
        t_list_augmented[car] += [t_list[car][-1]]
        d_list_augmented[car] += [d_list[car][-1]]
    t_list = t_list_augmented
    d_list = d_list_augmented

    constraints = []

    # 1.
    min_perceptible_time = 0.5  # seconds

    for car in new_cars:
        constraints += [s < t for s, t in zip(t_list[car], t_list[car][1:])]
    constraints += [min_perceptible_time*2 <= t2var[t] - t2var[s]  # *2 to get a crisper constrast
                    for s, t in temporal_constraints['lessThan']]
    constraints += [-min_perceptible_time < t2var[t] - t2var[s]
                    for s, t in temporal_constraints['equal']]
    constraints += [t2var[t] - t2var[s] < min_perceptible_time
                    for s, t in temporal_constraints['equal']]
    # 2. (a)
    # ds <= d1 <= de, and ds <= d2 <= de
    for car in new_cars:
        for i in range(0, len(d_list[car])-3, 3):
            constraints += [d_list[car][i] <= d_list[car][i+1],
                            d_list[car][i+1] <= d_list[car][i+3],
                            d_list[car][i] <= d_list[car][i+2],
                            d_list[car][i+2] <= d_list[car][i+3]]

    # 2. (b)
    # Let dq < dr < ds be three consecutive distances,
    # tq < tr < ts be their corresponding realtimes,
    # dq1 and dq2 be the distances for tq+(tr-tq)/3 and tq+2(tr-tq)/3, and
    # dr1 and dr2 be the distances for tr+(ts-tr)/3 and tr+2(ts-tr)/3, respectively.
    # Then we require:
    # (tr-tq)(dr1-dr) = (ts-tr)(dr-dq2)
    for car in new_cars:
        for i in range(len(t_list[car])-2):
            tq, tr, ts = tuple(t_list[car][i:i+3])
            dq2, dr, dr1 = tuple(d_list[car][3*i+2:3*i+5])
            constraints += [Equals((tr-tq)*(dr1-dr), (ts-tr)*(dr-dq2))]

    # 2. (c)
    # TODO if no stoppedAtFork event, force a minimum speed
    stop_speed = 1.0  # meters/second

    for car in new_cars:
        for i in range(1, len(t_list[car])-1):
            if str(t_list[car][i]) in temporal_constraints['stop']:
                delta_t = (t_list[car][i+1] - t_list[car][i])/3
                delta_d = d_list[car][3*i+1] - d_list[car][3*i]
                constraints += [delta_d/delta_t < Real(stop_speed)]

    # 2. (d)
    for car in new_cars:
        maxSpeed = config[car]['maxSpeed']
        for i in range(len(t_list[car])-1):
            tq, tr = tuple(t_list[car][i:i+2])
            dq, dq1, dq2, dr = tuple(d_list[car][3*i:3*i+4])
            # constraints += [3*(dq1-dq)/(tr-tq) <= maxSpeed,
            #                 3*(dr-dq2)/(tr-tq) <= maxSpeed]  # instantaneous speed
            constraints += [(dr-dq)/(tr-tq) <= Real(maxSpeed)]  # average speed

    with Solver(name=solver_name, logic=QF_NRA):
        m = get_model(And(constraints))
        if m == None:
            raise NoSMTSolutionError(
                f'SMT solver {solver_name} found no solutions.')

    t, d = {}, {}
    for car in new_cars:
        t[car] = [numeral_to_fp(m.get_py_value(T)) for T in t_list[car]]
        d[car] = [numeral_to_fp(m.get_py_value(D)) for D in d_list[car]]

    # Store parameters of the composite Bezier curves
    curves = {}
    for car in new_cars:
        curves[car] = {}
        # car's new time-distance curve
        t_comp = [t[car][0]]
        for i in range(len(t[car])-1):
            ts, te = t[car][i], t[car][i+1]
            ts1 = 2*ts/3 + te/3
            ts2 = ts/3 + 2*te/3
            t_comp += [ts1, ts2, te]
        curves[car]['degree'] = 3
        curves[car]['ctrlpts'] = [[t_comp[i], d[car][i]]
                                  for i in range(len(d[car]))]
        kv = [0, 0, 0, 0]
        for i in range(1, len(t[car])-1):
            kv += [t[car][i], t[car][i], t[car][i]]
        kv += [t[car][-1], t[car][-1], t[car][-1], t[car][-1]]
        curves[car]['knotvector'] = kv

    # New timing of events
    for car in new_cars:
        for time, events in car2time2events[car].items():
            f = events[0].frame
            if f != None:
                d_sim = car2frame2simDistance[car][f]
                t_new = distance_to_time(t[car], d[car], d_sim)
            else:
                t_new = numeral_to_fp(m.get_py_value(t2var[time]))
            for e in events:
                e.frame = realtime_to_frame(t_new, scenario.timestep)

    new_events = {}
    for car in new_cars:
        new_events[car] = []
        for es in car2time2events[car].values():
            new_events[car] += es

    return new_events, curves


def solution(scenario, config,
             sim_events,
             sim_trajectories,
             car_sizes):
    # All the given and new events
    import copy
    sim_events['illegal'] = []
    for event in sim_events['ego']:
        event_ill = copy.copy(event)
        event_ill.vehicle = 'illegal'
        sim_events['illegal'] += [event_ill]

    models, car2time2events = logical_solution(scenario, config, sim_events)

    if len(models) == 0:
        raise NoASPSolutionError('No ASP solution found!')

    # Find trajectories that preserve the order of events in the logical solution
    import copy
    old_nonegos = {car for car in scenario.events if not car in {
        'ego', 'illegal'}}
    new_events = None
    for i, model in enumerate(models):
        constraints, car2time2events_updated = model_to_constraints(
            model, copy.deepcopy(car2time2events), old_nonegos)

        print(f'Generating smooth trajecotries for {i}th ASP model...')
        try:
            new_events, curves = smooth_trajectories(scenario, config,
                                                     sim_trajectories,
                                                     constraints, car2time2events_updated)
            if has_collision(scenario, sim_trajectories, curves, car_sizes):
                print('Collision in SMT solution. Trying next ASP solution...')
            else:
                print('No collision in SMT solution.')
                break
        except NoSMTSolutionError as err:
            print(err.message)
    if not new_events:
        raise NoSMTSolutionError(
            'No SMT solution found for the ASP solutions!')

    # Update the events
    sim_events.update(new_events)

    return sim_events, curves

def simulate(init_lane, turn, config):
    blueprint = config['random'].choice(tuple(config['blueprints'].keys()))
    scenario = scenic.scenarioFromFile(
                    'src/scenariogen/core/seed_generators/footprint.scenic',
                    model=config['model'],
                    params={'timestep': config['timestep'],
                            'render': config['render'],
                            'config': {**config,
                                       'init_lane': init_lane.uid,
                                       'turns': (turn,),
                                       'init_progress': 0, # TODO min(100, distance to intersection)
                                       'blueprint': blueprint,
                                       'length': config['blueprints'][blueprint]['length'],
                                       'width': config['blueprints'][blueprint]['width'],
                                       'signal': SignalType.from_maneuver_type(turn)
                                      }
                            },
                    cacheImports=False
                    )
    scene, _ = scenario.generate(maxIterations=1)
    simulator = scenario.getSimulator()
    sim_result = simulator.simulate(
                        scene,
                        maxSteps=config['steps'],
                        maxIterations=1,
                        raiseGuardViolations=True
                        )
    return sim_result


def generate(config):
    network = Network.fromFile(config['map'])
    intersection = network.elements[config['intersection']]
    for li, lj in product(intersection.incomingLanes, intersection.incomingLanes):
        if li.uid == lj.uid:
            continue
        for mi in li.maneuvers:
            ti = mi.type
            # ego: simulate autopilot on li, record events
            try:
                ego_sim_result = simulate(li, ti, config)
            except NonegoCollisionError as err:
                print(f'Collision between nonegos {err.nonego} and {err.other}, discarding the simulation.')
                continue
            except SimulationCreationError:
                print('Failed to create scenario.')
                continue
            except GuardViolation:
                print('Guard violated in simulation.')
                continue
            
            for mj in lj.maneuvers:
                tj = mj.type
                try:
                    nonego_sim_result = simulate(lj, tj, config)
                except NonegoCollisionError as err:
                    print(f'Collision between nonegos {err.nonego} and {err.other}, discarding the simulation.')
                    continue
                except SimulationCreationError:
                    print('Failed to create scenario.')
                    continue
                except GuardViolation:
                    print('Guard violated in simulation.')
                    continue
                new_events, new_timings = solution(ego_sim_result, nonego_sim_result, config)
                
                

        

