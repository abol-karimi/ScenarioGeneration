
#include "src/scenariogen/predicates/abstractions.lp".

%--- Auxiliary predicates ---
leftAfter(V2, V1):-
  leftAtTime(V1, T1),
  leftAtTime(V2, T2),
  1 = @lessThan(T1, T2).

%---------- leader following ----------
follows(V2, V1):-
  enteredFromLaneAtTime(V1, L, T1),
  enteredFromLaneAtTime(V2, L, T2),
  1 = @lessThan(T1, T2),
  leftToLane(V1, L),
  leftToLane(V2, L).

%---------- Merging ----------
mergedWithToLane(V2, V1, L):-
  enteredFromLane(V1, L1),
  enteredFromLane(V2, L2),
  L1 != L2,
  leftToLane(V1, L),
  leftToLane(V2, L).

mergedBetweenToLane(V2, V3, V1, L):-
  mergedWithToLane(V2, V1, L),
  mergedWithToLane(V2, V3, L),
  leftAfter(V2, V1),
  leftAfter(V3, V2).

mergedBetweenToLane(V2, V1, V3, L):-
  mergedBetweenToLane(V2, V3, V1, L).

%---------- Diverging ----------
diveregedToLanes(V1, V2, L1, L2):-
  enteredFromLane(V1, L),
  enteredFromLane(V2, L),
  leftToLane(V1, L1),
  leftToLane(V2, L2),
  L1 != L2.


% V1 and V2 enter the intersection from two different lanes L1 and L2,
% and exit the intersection from two different lanes L3 and L4,
% where the connecting lanes overlap.
crossedPathWith(V1, V2):-
  enteredFromLane(V1, L1),
  enteredFromLane(V2, L2),
  L1 != L2,
  leftToLane(V1, L3),
  leftToLane(V2, L4),
  L3 != L4,
  lanePrecedes(L1, L13), lanePrecedes(L13, L3),
  lanePrecedes(L2, L24), lanePrecedes(L24, L4),
  overlaps(L13, L24).


% When two vehicles enter the intersection from two different lanes,
% and exit from two different lanes,
% where the connecting lanes do not overlap.
nonConflictPathWith(V1, V2):-
  enteredFromLane(V1, L1),
  enteredFromLane(V2, L2),
  L1 != L2,
  leftToLane(V1, L3),
  leftToLane(V2, L4),
  L3 != L4,
  lanePrecedes(L1, L13), lanePrecedes(L13, L3),
  lanePrecedes(L2, L24), lanePrecedes(L24, L4),
  not overlaps(L13, L24).
