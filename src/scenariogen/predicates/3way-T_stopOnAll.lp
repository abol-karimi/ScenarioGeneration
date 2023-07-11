#script(python)
# Model parameters
min_perceptible_time = 0.5

import clingo
from scenariogen.core.events import term_to_time

def lessThan(S, T):
  lt = min_perceptible_time < term_to_time[T.name] - term_to_time[S.name]
  return clingo.Number(1) if lt else clingo.Number(0)

def equal(S, T):
  eq = abs(term_to_time[S.name] - term_to_time[T.name]) < {min_perceptible_time}
  return clingo.Number(1) if eq else clingo.Number(0)
#end.

%----------------------------------------------
%---Auxiliary predicates for geometric facts---
%----------------------------------------------
branchOf(Lane, Fork):-
  laneFromTo(Lane, Fork, _).

forkOnContinuingHighway(F):-
  laneFromTo(L, F, _),
  laneCorrectSignal(L, off).

forkOnTerminatingHighway(F):-
  hasStopSign(F).

forkOnOppositeDirection(F1, F2):-
  isOnRightOf(F2, F),
  isOnRightOf(F, F1).
forkOnOppositeDirection(F1, F2):-
  forkOnOppositeDirection(F2, F1).

%---------------------------------------------
%---Auxiliary predicates for traffic events---
%---------------------------------------------
arrivedAtFork(Vehicle, Fork):-
  arrivedAtForkAtTime(Vehicle, Fork, _).

arrivedAtTime(V, T):-
  arrivedAtForkAtTime(V, _, T).

enteredAtTime(V, T):-
  enteredForkAtTime(V, _, T).

signaledAtFork(V, S, F):-
  signaledAtForkAtTime(V, S, F, _).

signaledLeft(V):-
  signaledAtFork(V, left, _).

%--------------------------------------------
%---Auxiliary predicates for traffic rules---
%--------------------------------------------
arrivedFromOppositeDirection(V1, V2):-
  arrivedAtFork(V1, F1),
  arrivedAtFork(V2, F2),
  forkOnOppositeDirection(F1, F2).

arrivedFromContinuingHighway(V):-
  arrivedAtFork(V, F),
  forkOnContinuingHighway(F).

arrivedFromTerminatingHighway(V):-
  arrivedAtFork(V, F),
  forkOnTerminatingHighway(F).

requestedLane(Vehicle, Lane):-
  signaledAtFork(Vehicle, Signal, Fork),
  branchOf(Lane, Fork),
  laneCorrectSignal(Lane, Signal).
 
%---------------- Rules ---------------
% http://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?lawCode=VEH&division=11.&title=&part=&chapter=4.&article=
%--------------------------------------
% 21801 (a):
% The driver of a vehicle intending to turn to the left or to complete a U-turn upon a highway,
%  shall yield the right-of-way to all vehicles approaching from the opposite direction
%  which are close enough to constitute a hazard at any time during the turning movement,
%  and shall continue to yield the right-of-way to the approaching vehicles
%  until the left turn or U-turn can be made with reasonable safety.
violatesRightOfForRule(V1, V2, leftTurnFromContinuingHighway):-
  V1 != V2,
  signaledLeft(V1),
  arrivedFromOppositeDirection(V1, V2),
  requestedLane(V1, L1),
  requestedLane(V2, L2),
  overlaps(L1, L2),
  arrivedAtTime(V2, Ta),
  enteredLaneAtTime(V1, L2, Te1),
  1 = @lessThan(Ta, Te1),
  leftLaneAtTime(V2, L1, Tl2),
  1 = @lessThan(Te1, Tl2).

% 21801 (b):
% A driver having yielded as prescribed in subdivision (a),
%  and having given a signal when and as required by this code,
%  may turn left or complete a U-turn,
%  and the drivers of vehicles approaching the intersection from the opposite direction
%  shall yield the right-of-way to the turning vehicle.
violatesRightOfForRule(V2, V1, yieldToLeftTurnFromContinuingHighway):-
  V1 != V2,
  signaledLeft(V1),
  arrivedFromOppositeDirection(V1, V2),
  requestedLane(V1, L1),
  requestedLane(V2, L2),
  overlaps(L1, L2),
  arrivedAtTime(V2, Ta),
  enteredLaneAtTime(V1, L2, Te1),
  1 = @lessThan(Te1, Ta), % V1 enters the overlap earlier than V2 arrives at the intersection
  leftLaneAtTime(V1, L2, Tl1),
  enteredLaneAtTime(V2, L1, Te2),
  1 = @lessThan(Te2, Tl1). % V2 enters the overlap earlier than V1 leaves it

% 22450 (a):
% The driver of any vehicle approaching a stop sign at the entrance to, or within, an intersection
%  shall stop at a limit line, if marked,
%  otherwise before entering the crosswalk on the near side of the intersection.
% If there is no limit line or crosswalk,
%  the driver shall stop at the entrance to the intersecting roadway.
% 21802 (a):
% The driver of any vehicle approaching a stop sign at the entrance to, or within, an intersection
%  shall stop as required by Section 22450.
stoppedAtFork(V, F):-
  stoppedAtForkAtTime(V, F, T).

violatesRule(V, stopAtSign):-
  arrivedAtFork(V, F),
  hasStopSign(F),
  not stoppedAtFork(V, F).
 
% The driver shall then yield the right-of-way
%  to any vehicles which have approached from another highway,
%  or which are approaching so closely as to constitute an immediate hazard,
%  and shall continue to yield the right-of-way to those vehicles until he or she can proceed with reasonable safety.
violatesRightOfForRule(V1, V2, yieldToCrossing):-
  V1 != V2,
  arrivedFromTerminatingHighway(V1),
  arrivedFromContinuingHighway(V2),
  requestedLane(V1, L1),
  requestedLane(V2, L2),
  overlaps(L1, L2),
  arrivedAtTime(V2, Ta),
  enteredAtTime(V1, Te),
  1 = @lessThan(Ta, Te), % V2 arrives earlier than V1 enters
  enteredLaneAtTime(V1, L2, Tle),
  leftLaneAtTime(V2, L1, Tll),
  1 = @lessThan(Tle, Tll). % V1 enters the overlap earlier than V2 leaves it

% 21802 (b):
% A driver having yielded as prescribed in subdivision (a) may proceed to enter the intersection,
%  and the drivers of all other approaching vehicles shall yield the right-of-way
%  to the vehicle entering or crossing the intersection.
% 21802 (c):
% This section does not apply where stop signs are erected upon all approaches to an intersection.
violatesRightOfForRule(V2, V1, yieldToYieldedToCrossing):-
  V1 != V2,
  arrivedFromTerminatingHighway(V1),
  arrivedFromContinuingHighway(V2),
  requestedLane(V1, L1),
  requestedLane(V2, L2),
  overlaps(L1, L2),
  enteredAtTime(V1, Te),
  arrivedAtTime(V2, Ta),
  1 = @lessThan(Te, Ta), % V1 enters before V2 arrives
  enteredLaneAtTime(V2, L1, Tle),
  leftLaneAtTime(V1, L2, Tll),
  1 = @lessThan(Tle, Tll). % V2 enters the overlap earlier than V1 leaves it

%-------------------------------------------------
violatesRightOf(V1, V2):-
  violatesRightOfForRule(V1, V2, _).



