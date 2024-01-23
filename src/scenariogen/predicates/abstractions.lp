
% time abstraction of all event predicates:
arrivedFromLane(V, L):-
  arrivedFromLaneAtTime(V, L, _).

signaled(V, S):-
  signaledAtTime(V, S, _).

stopped(V):-
  stoppedAtTime(V, _).

moved(V):-
  movedAtTime(V, _).

enteredLane(V, L):-
  enteredLaneAtTime(V, L, _).

enteredFromLane(V, L):-
  enteredFromLaneAtTime(V, L, _).

leftLane(V, L):-
  leftLaneAtTime(V, L, _).

leftToLane(V, L):-
  leftToLaneAtTime(V, L, _).

appearedTo(V1, V2):-
  appearedToAtTime(V1, V2, _).

disappearedFrom(V1, V2):-
  disappearedFromAtTime(V1, V2, _).

actorSpawnedAtAlongLane(V, P, L):-
  actorSpawnedAtAlongLaneAtTime(V, P, L, _).

collidedWith(V, A):-
  collidedWithAtTime(V, A, _).

% Other abstractions:
arrivedAtTime(V, T):-
  arrivedFromLaneAtTime(V, _, T).

enteredAtTime(V, T):-
  enteredFromLaneAtTime(V, _, T).

leftAtTime(V, T):-
  leftToLaneAtTime(V, _, T).

actorSpawnedOnLane(V, L):-
  actorSpawnedAtAlongLane(V, _, L).
