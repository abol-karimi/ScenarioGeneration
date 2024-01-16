
%--------------------------------------------
%------ Auxiliary geometric predicates ------
%--------------------------------------------
opposingArrivalLanes(L1, L2):-
  isOnRightOf(L1, L),
  isOnRightOf(L, L2).

opposingArrivalLanes(L1, L2):-
  opposingArrivalLanes(L2, L1).

lanesOnDifferentHighways(L1, L2):-
  isOnRightOf(L1, L2).

lanesOnDifferentHighways(L1, L2):-
  isOnRightOf(L2, L1).

%---------------------------------------------
%------- Auxiliary traffic predicates -------
%---------------------------------------------
eventTime(T):-
  arrivedFromLaneAtTime(_, _, T).

eventTime(T):-
  signaledAtTime(_, _, T).

eventTime(T):-
  stoppedAtTime(_, T).

eventTime(T):-
  movedAtTime(_, T).

eventTime(T):-
  enteredFromLaneAtTime(_, _, T).

eventTime(T):-
  enteredLaneAtTime(_, _, T).

eventTime(T):-
  leftLaneAtTime(_, _, T).

eventTime(T):-
  leftToLaneAtTime(_, _, T).

changedSignalBetween(V, T1, T2):-
  signaledAtTime(V, _, Tm),
  eventTime(T1),
  eventTime(T2),
  lessThan(T1, Tm),
  lessThan(Tm, T2).

signaledAtArrivalFromLane(V, S, La):-
  signaledAtTime(V, S, Ts),
  arrivedFromLaneAtTime(V, La, Ta),
  lessThan(Ts, Ta),
  not changedSignalBetween(V, Ts, Ta).

signaledLeftAtArrival(Vehicle):-
  signaledAtArrivalFromLane(Vehicle, left, _).

arrivedFromTheOppositeDirection(V1, V2):-
  arrivedFromLane(V1, L1), arrivedFromLane(V2, L2),
  opposingArrivalLanes(L1, L2).

arrivedFromDifferentHighways(V1, V2):-
  arrivedFromLane(V1, L1),
  arrivedFromLane(V2, L2),
  lanesOnDifferentHighways(L1, L2).

arrivedFromRightOf(V1, V2):-
  arrivedFromLane(V1, L1),
  arrivedFromLane(V2, L2),
  isOnRightOf(L1, L2).

enteredAfter(V, T):-
  enteredAtTime(V, Te),
  eventTime(T),
  lessThan(T, Te).


%--------------------------------------------
%---Auxiliary predicates for traffic rules---
%--------------------------------------------
requestedLane(V, L):-
  signaledAtArrivalFromLane(V, S, La),
  lanePrecedes(La, L),
  laneCorrectSignal(L, S).


%---------------- Rules ---------------
% http://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?lawCode=VEH&division=11.&title=&part=&chapter=4.&article=
%--------------------------------------
% 21800 (a):
% The driver of a vehicle approaching an intersection shall yield the right-of-way
%  to any vehicle which has entered the intersection from a different highway.
violatesRightOfForRule(V1, V2, yieldToInside):-
  V1 != V2,
  arrivedFromLaneAtTime(V1, La, Ta),
  enteredAtTime(V2, Te),
  lessThan(Te, Ta),
  arrivedFromDifferentHighways(V1, V2),
  requestedLane(V1, L1),
  requestedLane(V2, L2),
  overlaps(L1, L2),
  leftLaneAtTime(V2, L1, T1),
  enteredLaneAtTime(V1, L2, T2),
  lessThan(T2, T1).

%---------------------------------------------------------------------------------
% 21800 (c)
% When two vehicles enter an intersection from different highways at the same time 
%  and the intersection is controlled from all directions by stop signs, 
%  the driver of the vehicle on the left shall yield the right-of-way 
%  to the vehicle on his or her immediate right.
violatesRightOfForRule(V1, V2, yieldToRight):-
  V1 != V2,
  enteredAtTime(V1, Te1),
  enteredAtTime(V2, Te2),
  equal(Te1, Te2),
  arrivedFromRightOf(V2, V1),
  requestedLane(V1, L1),
  requestedLane(V2, L2),
  overlaps(L1, L2),
  leftLaneAtTime(V2, L1, TV2L1l),
  enteredLaneAtTime(V1, L2, TV1L2e),
  lessThan(TV1L2e, TV2L1l). % V1 entered the overlap before V2 left it

%--------------------------------------------------------------------------------------------
% 21801 (a)
% The driver of a vehicle intending to turn to the left or to complete a U-turn upon a highway,
%  shall yield the right-of-way to all vehicles approaching from the opposite direction
%  which are close enough to constitute a hazard at any time during the turning movement,
%  and shall continue to yield the right-of-way to the approaching vehicles
%  until the left turn or U-turn can be made with reasonable safety.
violatesRightOfForRule(V1, V2, leftTurn):-
  V1 != V2,
  signaledLeftAtArrival(V1),
  arrivedFromTheOppositeDirection(V1, V2),
  requestedLane(V1, L1),
  requestedLane(V2, L2),
  overlaps(L1, L2),
  arrivedAtTime(V2, Ta),
  enteredLaneAtTime(V1, L2, Te1),
  lessThan(Ta, Te1),
  leftLaneAtTime(V2, L1, Tl2),
  lessThan(Te1, Tl2).

% 22450 (a):
% The driver of any vehicle approaching a stop sign at the entrance to, or within, an intersection
%  shall stop at a limit line, if marked,
%  otherwise before entering the crosswalk on the near side of the intersection.
% If there is no limit line or crosswalk,
%  the driver shall stop at the entrance to the intersecting roadway.
% 21802 (a):
% The driver of any vehicle approaching a stop sign at the entrance to, or within, an intersection
%  shall stop as required by Section 22450.
stoppedAfterArrivalFromLane(V, L):-
  arrivedFromLaneAtTime(V, L, Ta),
  stoppedAtTime(V, Ts),
  lessThan(Ta, Ts),
  incomingLane(L),
  enteredAtTime(V, Te),
  lessThan(Ts, Te).

stoppedAfterArrivalFromLane(V, L):-
  arrivedFromLaneAtTime(V, L, Ta),
  stoppedAtTime(V, Ts),
  lessThan(Ta, Ts),
  incomingLane(L),
  not enteredAfter(V, Ts).

violatesRule(V, stopAtSign):-
  arrivedFromLaneAtTime(V, L, Ta),
  hasStopSign(L),
  incomingLane(L),  
  enteredAtTime(V, Te),
  not stoppedAfterArrivalFromLane(V, L).

% 22526 (a) (Signalized intersection?)
% Notwithstanding any official traffic control signal indication to proceed,
%  a driver of a vehicle shall not enter an intersection or marked crosswalk
%  unless there is sufficient space on the other side of the intersection or marked crosswalk
%  to accommodate the vehicle driven without obstructing the through passage of vehicles from either side.
