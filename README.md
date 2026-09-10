# ScenarioGeneration

Code for the paper **"Diverse Traffic Scenario Generation for Autonomous Vehicles using
Fuzzing"**, Abolfazl Karimi and Parasara Sridhar Duggirala, *ACM/IEEE International
Conference on Cyber-Physical Systems (ICCPS)*, 2026.

## The idea

Coverage-guided fuzzing works because coverage is a proxy for "have I explored something
new?" For programs, code coverage is a reasonable proxy. For an autonomous vehicle
navigating traffic, it is a bad one: two scenarios can execute nearly identical code
paths while being completely different driving situations, and two scenarios that look
alike in code can differ in whether the vehicle yielded, ran a stop sign, or blocked an
intersection. Off-the-shelf fuzzers such as libFuzzer and AFL support only code
coverage, so they optimize for the wrong thing.

This project replaces the coverage criterion. Instead of counting code, we count
**predicates derived from the system's end-to-end requirements** — the traffic rules the
vehicle is actually supposed to obey. A scenario is "new" if it puts the vehicle in a
combination of rule-relevant conditions that no previous scenario did. That criterion
then drives the fuzzer, giving a **predicate-coverage-guided fuzzer (PCGF)**.

The claim being tested is narrow and falsifiable: *does changing the coverage criterion
actually produce a more diverse set of test scenarios, or does it just produce a
different number on a different metric?*

## Research questions and results

**RQ1 — Do predicate-coverage-guided fuzzers generate more diverse scenarios than
code-coverage-driven ones?** Yes. PCGF outperforms both a random-fuzzer baseline and
Atheris, a libFuzzer-based code-coverage fuzzer for Python, across the agents tested.

**RQ2 — Which fuzzing algorithm and power schedule suits this problem?** Several are
implemented: `PCGF-Entropic`, `PCGF-AFLFast`, and `PCGF-Entropic-MixedFeedback`, which
combines predicate and code feedback. Entropic is implemented here in Python by
translating libFuzzer's C++ source, so that our fuzzer can pair that schedule with
predicate-coverage feedback; it differs from libFuzzer's in not considering fuzz-input
size, so it will not replace a candidate with a smaller one of equal coverage. Entropic
performs best, and the random fuzzer is consistently worst.

**RQ3 — Do scenarios generated against one AV implementation transfer to others?** To a
large extent, yes, which matters because it means a corpus built against one stack
retains value when testing another.

## What is in here

```
src/scenariogen/
  core/          scenario representation, mutation, fuzzing loop
  predicates/    the traffic-rule predicates that define the coverage criterion
  simulators/    CARLA and Scenic Newtonian simulator backends
  interfaces/    integration points, incl. the CARLA leaderboard agent interface
  scripts/       command-line entry points
evaluation/
  experiments/   fuzzer entry points (PCGF.py, Atheris.py, Random.py, ...)
                 and the RQ1, RQ2, RQ3 experiment drivers
  agents/        the AV implementations under test, as Scenic definitions
  seeds/         seed scenarios the fuzzers start from
Apptainer/       container definitions (the primary supported path)
Docker/          Dockerfiles
Longleaf/        SLURM job scripts for UNC's Longleaf cluster
tests/
```

**Structure-aware mutation.** A traffic scenario is highly structured and constrained,
so mutating a bit-level representation almost always yields something invalid. The
mutators here operate on the Python object representation of a scenario instead, so
every mutant is still a valid object of the same type. They copy or move a vehicle and
its trajectory forward or backward along its route; copy or move one to a different
route, preserving its local coordinates in the curvilinear frame; remove a vehicle;
speed a vehicle up or slow it down by a random factor over a random interval; mutate the
ego vehicle's route; and add or remove turn-signal events. Trajectories are splines, so
a mutation can also perturb control points for local search. Each fuzzing step applies a
random number of these.

Both baselines use the same mutators, so the comparison isolates the coverage criterion
rather than confounding it with mutation quality. Atheris is itself libFuzzer-based and
uses the Entropic power schedule; the difference under test is that it is guided by code
coverage while PCGF is guided by predicate-set coverage.

**Agents evaluated.** Four AV implementations, defined under `evaluation/agents/`:
CARLA's privileged Autopilot (driven by its traffic manager), CARLA's rule-based
`BehaviorAgent`, a `BehaviorAgent` variant with Responsibility-Sensitive Safety, and a
Scenic agent run under Scenic's built-in Newtonian simulator.

## Running it

The supported path is containers. Build the Apptainer images in dependency order,
starting from `Apptainer/definitions/scenariogen-bionic.apptainer` and following the
dependencies in the other definition files. Dockerfiles are in `Docker/` if you prefer
those. Python dependencies are in `requirements.txt`.

To fuzz, run one of the entry points in `evaluation/experiments/`: `PCGF.py` for the
predicate-coverage-guided fuzzer, `Atheris.py` and `Random.py` for the baselines.

To reproduce the paper's experiments, see the drivers in `evaluation/experiments/RQ1`,
`RQ2`, and `RQ3`. `evaluation/experiments/RQ1/trials_slurm.py` is a complete worked
example of configuring and launching a campaign. The paper's results come from roughly
10,000 hours of simulation on a CPU/GPU cluster, so a full reproduction is a cluster job
rather than a laptop one; `Longleaf/` holds the SLURM scripts used for it.

## Citation

```bibtex
@inproceedings{Karimi.2026,
  title={Diverse Traffic Scenario Generation for Autonomous Vehicles using Fuzzing},
  author={Karimi, Abolfazl and Duggirala, Parasara Sridhar},
  booktitle={ACM/IEEE International Conference on Cyber-Physical Systems (ICCPS)},
  year={2026}
}
```

## Related

- [ScenarioComplexity](https://github.com/abol-karimi/ScenarioComplexity) — generating
  test cases of increasing complexity by constraint solving (ICCPS 2022).
- [FormalizedTrafficRules](https://github.com/abol-karimi/FormalizedTrafficRules) — the
  traffic-rule monitor the predicates come from (ICCPS 2020).
