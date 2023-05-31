"""
Research question:
  How does the performance of open-loop and closed-loop fuzzing compare
  in terms of number of accidents for a fixed computation budget?

Open-loop fuzzing:
The set of seeds are selected without simulating the SUT.
New seeds are generated using mutation, and seeds are selected using
a scoring function on the space of inputs (to the SUT).

Closed-loop fuzzing:
The SUT is simulated on each generated seed before being selected.
New seeds are generated using mutation.
Seed selection is guided by a scoring function defined on the space of outputs (of the SUT)
which may subsume the space of inputs.
"""