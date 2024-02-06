from . import baselines_vs_PCGF_per_fuzz_input
from . import baselines_vs_PCGF_per_time
from . import baselines_vs_PCGF_predicate_distribution
from . import baselines_vs_PCGF_valid
from . import baselines_vs_PCGF_violations_per_fuzz_input
from . import target_vs_surrogate_violations_per_fuzz_input
from . import target_vs_surrogate_violations_per_time

coverage_plots = [
  baselines_vs_PCGF_per_time.plot,
]

baseline_plots = [
  # baselines_vs_PCGF_per_fuzz_input.plot,
  baselines_vs_PCGF_per_time.plot,
  # baselines_vs_PCGF_predicate_distribution.plot,
  # baselines_vs_PCGF_valid.plot,
  # baselines_vs_PCGF_violations_per_fuzz_input.plot,
  # baselines_vs_PCGF_violations_per_time.plot,
]

surrogate_plots = [
  target_vs_surrogate_violations_per_fuzz_input.plot,
  target_vs_surrogate_violations_per_time.plot,
]

