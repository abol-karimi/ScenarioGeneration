%----------------------------------------------
%---Auxiliary predicates for geometric facts---
%----------------------------------------------
branchOf(Lane, Fork):-
  laneFromTo(Lane, Fork, _).

forksOnSameHighway(Fork1, Fork2):-
  isOnRightOf(Fork1, F),
  isOnRightOf(F, Fork2).

forksOnSameHighway(Fork1, Fork2):-
  forksOnSameHighway(Fork2, Fork1).

forksOnDifferentHighways(F1, F2):-
  isOnRightOf(F1, F2).

forksOnDifferentHighways(F1, F2):-
  isOnRightOf(F2, F1).

%---------------------------------------------
%---Auxiliary predicates for traffic events---
%---------------------------------------------
eventTime(T):-
  arrivedAtForkAtTime(_, _, T).

eventTime(T):-
  signaledAtTime(_, _, T).

eventTime(T):-
  enteredForkAtTime(_, _, T).

eventTime(T):-
  enteredLaneAtTime(_, _, T).

eventTime(T):-
  leftLaneAtTime(_, _, T).

eventTime(T):-
  exitedFromAtTime(_, _, T).

arrivedAtFork(Vehicle, Fork):-
  arrivedAtForkAtTime(Vehicle, Fork, _).

arrivedAtTime(V, T):-
  arrivedAtForkAtTime(V, _, T).

changedSignalBetween(V, T1, T2):-
  signaledAtTime(V, _, Tm),
  eventTime(T1),
  eventTime(T2),
  1 = @lessThan(T1, Tm),
  1 = @lessThan(Tm, T2).

signaledAtFork(V, S, F):-
  signaledAtTime(V, S, Ts),
  arrivedAtForkAtTime(V, F, Ta),
  1 = @lessThan(Ts, Ta),
  not changedSignalBetween(V, Ts, Ta).

signaledLeft(Vehicle):-
  signaledAtFork(Vehicle, left, _).

arrivedFromSameHighway(V1, V2):-
  arrivedAtFork(V1, F1), arrivedAtFork(V2, F2),
  forksOnSameHighway(F1, F2).

%--------------------------------------------
%---Auxiliary predicates for traffic rules---
%--------------------------------------------
requestedLane(Vehicle, Lane):-
  signaledAtFork(Vehicle, Signal, Fork),
  branchOf(Lane, Fork),
  laneCorrectSignal(Lane, Signal).

%---------------- Rules ---------------
% http://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?lawCode=VEH&division=11.&title=&part=&chapter=4.&article=
%--------------------------------------
% 21800 (a):
% The driver of a vehicle approaching an intersection shall yield the right-of-way
%  to any vehicle which has entered the intersection from a different highway.
violatesRightOfForRule(V1, V2, yieldToInside):-
  V1 != V2,
  enteredForkAtTime(V1, F1, Te1),
  enteredForkAtTime(V2, F2, Te2),
  forksOnDifferentHighways(F1, F2),
  requestedLane(V1, L1),
  requestedLane(V2, L2),
  overlaps(L1, L2),
  1 = @lessThan(Te2, Te1),
  leftLaneAtTime(V2, L1, T1),
  enteredLaneAtTime(V1, L2, T2),
  1 = @lessThan(T2, T1).

%---------------------------------------------------------------------------------
% 21800 (b)(1)
% When two vehicles enter an intersection from different highways at the same time,
%  the driver of the vehicle on the left shall yield the right-of-way
%  to the vehicle on his or her immediate right.
violatesRightOfForRule(V1, V2, yieldToRight):-
  V1 != V2,
  enteredForkAtTime(V1, F1, Te1),
  enteredForkAtTime(V2, F2, Te2),
  isOnRightOf(F2, F1),
  requestedLane(V1, L1),
  requestedLane(V2, L2),
  overlaps(L1, L2),
  1 = @equal(Te1, Te2),
  leftLaneAtTime(V2, L1, T1),
  enteredLaneAtTime(V1, L2, T2),
  1 = @lessThan(T2, T1).

%--------------------------------------------------------------------------------------------
% 21801 (a)
% The driver of a vehicle intending to turn to the left or to complete a U-turn upon a highway,
%  shall yield the right-of-way to all vehicles approaching from the opposite direction
%  which are close enough to constitute a hazard at any time during the turning movement,
%  and shall continue to yield the right-of-way to the approaching vehicles
%  until the left turn or U-turn can be made with reasonable safety.
violatesRightOfForRule(V1, V2, leftTurn):-
  V1 != V2,
  signaledLeft(V1),
  arrivedFromSameHighway(V1, V2),
  requestedLane(V1, L1),
  requestedLane(V2, L2),
  overlaps(L1, L2),
  arrivedAtTime(V2, Ta),
  enteredLaneAtTime(V1, L2, Te1),
  1 = @lessThan(Ta, Te1),
  leftLaneAtTime(V2, L1, Tl2),
  1 = @lessThan(Te1, Tl2).

%--------------------------------------------------------------------------------------------
% 22526 (a) (Signalized intersection?)
% Notwithstanding any official traffic control signal indication to proceed,
%  a driver of a vehicle shall not enter an intersection or marked crosswalk
%  unless there is sufficient space on the other side of the intersection or marked crosswalk
%  to accommodate the vehicle driven without obstructing the through passage of vehicles from either side.
% mustYieldToForRuleAtTime(V1, V2, antiGridlock, T):-
%   V1 != V2,
%   requestedLane(V1, L1),
%   requestedLane(V2, L2),
%   laneFromTo(L1, _, E),
%   laneFromTo(L2, _, E),
%   enteredAtTime(V1, T1),
%   enteredAtTime(V2, T2),
%   T1 > T2,
%   time(T),
%   T >= T1,
%   not leftLaneByTime(V2, L2, T).

% violatesRightOfForRule(V1, V2, antiGridlock):-
%   mustYieldToForRuleAtTime(V1, V2, antiGridlock, T),
%   enteredByTime(V1, T).

%-------------------------------------------------
violatesRightOf(V1, V2):-
  violatesRightOfForRule(V1, V2, _).

