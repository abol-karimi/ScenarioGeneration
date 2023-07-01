#!/usr/bin/env python3.8

# System Under Test:
#  A VUT (Vehicle Under Test) following a predefined route
#
# SUT input:
#  seed json file
# 
# SUT output:
#  success/failure (exit code, exceptions)
#
# Coverage criteria:
#    Coverage is a property of a set of seeds (i.e. a seed corpus),
#    in our case, the set of predicates that are covered
#  Option 1:
#    predicate coverage is measured after the fuzzer is done.
#    The fuzzer may internally use other coverage criteria such as code coverage
#  Option 2:
#    the fuzzer takes a coverage function as an input and
#    chooses samples accordingly to maximize the given coverage criteria

# Experiment hypothesis:
#  None of the available fuzzers acheive good predicate coverage

# Available python fuzzers:
#  Atheris (based on libfuzzer)
#  Hypothesis (rule-based stateful testing)
#  Pythonfuzz
#  PyJFuzz, gramfuzz
#  fuzzing
#  python-afl