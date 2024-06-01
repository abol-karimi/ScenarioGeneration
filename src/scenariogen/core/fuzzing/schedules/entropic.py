from collections import Counter
import math
import logging
import heapq

from .power import PowerSchedule


class EntropicSchedule(PowerSchedule):
    kFeatureSetSize = 1 << 21
    kMaxMutationFactor = 20
    kSparseEnergyUpdates = 100

    def __init__(self, randomizer_seed, FeatureFrequencyThreshold, NumberOfRarestFeatures):
        super().__init__(randomizer_seed)
        self.FeatureFrequencyThreshold = FeatureFrequencyThreshold
        self.NumberOfRarestFeatures = NumberOfRarestFeatures
        self.NumExecutedMutations = 0
        self.Weights = None

        self.DistributionNeedsUpdate = True
        self.RareFeatures = set()
        self.RareFeaturesHeap = [] # a min-heap with negated frequencies (to use as a max-heap)

    def choose(self, fuzz_candidates):
        """Choose weighted by normalized energy."""
        logger = logging.getLogger(__name__)
        self.UpdateCorpusDistribution(fuzz_candidates)
        fuzz_candidate = self.random.choices(fuzz_candidates,
                                             weights=self.Weights)[0]
        logger.debug(f'Chose fuzz-candidate with fuzz-input-hash {fuzz_candidate.fuzz_input.hexdigest}')
        return fuzz_candidate

    def UpdateCorpusDistribution(self, fuzz_candidates):
        """
        Updates the probability distribution for the units in the corpus.
        Must be called whenever the corpus or unit weights are changed.
        
        Hypothesis: inputs that maximize information about globally rare features
        are interesting.
        """
        # Skip update if no seeds or rare features were added/deleted.
        # Sparse updates for local change of feature frequencies,
        # i.e., randomly do not skip.
        if not self.DistributionNeedsUpdate \
            and self.random.choices((True, False),
                                    weights=(self.kSparseEnergyUpdates, 1)):
            return

        self.DistributionNeedsUpdate = False

        self.Weights = [0]*len(fuzz_candidates)

        VanillaSchedule = True
        for II in fuzz_candidates:
            if (II.NeedsEnergyUpdate and II.energy != 0.0):
                II.NeedsEnergyUpdate = False
                self.UpdateEnergy(II, len(self.RareFeatures))

        for i in range(len(fuzz_candidates)):
            if len(fuzz_candidates[i].feature_frequency) == 0:
                # If the seed doesn't represent any features, assign zero energy.
                self.Weights[i] = 0.
            elif (fuzz_candidates[i].NumExecutedMutations / self.kMaxMutationFactor >
                    self.NumExecutedMutations / len(fuzz_candidates)):
                # If the seed was fuzzed a lot more than average, assign zero energy.
                self.Weights[i] = 0.
            else:
                # Otherwise, simply assign the computed energy.
                self.Weights[i] = fuzz_candidates[i].energy

            # If energy for all seeds is zero, fall back to vanilla schedule.
            if (self.Weights[i] > 0.0):
                VanillaSchedule = False

        if VanillaSchedule:
            for i in range(len(fuzz_candidates)):
                self.Weights[i] = i + 1 \
                                    if len(fuzz_candidates[i].feature_frequency) > 0 \
                                    else 0.

    def UpdateEnergy(self, II, GlobalNumberOfFeatures):
        """ Assign more energy to a high-entropy seed, i.e., that reveals more
        information about the globally rare features in the neighborhood of the
        seed. Since we do not know the entropy of a seed that has never been
        executed we assign fresh seeds maximum entropy and let II.energy approach
        the true entropy from above. If ScalePerExecTime is true, the computed
        entropy is scaled based on how fast this input executes compared to the
        average execution time of inputs. The faster an input executes, the more
        energy gets assigned to the input.
        """
        II.energy = 0.0
        II.SumIncidence = 0.0

        # Apply add-one smoothing to locally discovered features.
        for freq in self.feature_frequency.values():
            LocalIncidence = freq + 1
            II.energy -= LocalIncidence * math.log(LocalIncidence)
            II.SumIncidence += LocalIncidence

        # Apply add-one smoothing to locally undiscovered features.
        #   PreciseEnergy -= 0; # since log(1.0) == 0)
        II.SumIncidence += GlobalNumberOfFeatures - len(self.feature_frequency)

        # Add a single locally abundant feature apply add-one smoothing.
        AbdIncidence = II.NumExecutedMutations + 1
        II.energy -= AbdIncidence * math.log(AbdIncidence)
        II.SumIncidence += AbdIncidence

        # Normalize.
        if II.SumIncidence != 0:
            II.energy = II.energy / II.SumIncidence + math.log(II.SumIncidence)

    def AddRareFeature(self, feature, fuzz_candidates):
        # Maintain *at least* NumberOfRarestFeatures many rare features
        # and all features with a frequency below ConsideredRare.
        # Remove all other features.
        while len(self.RareFeatures) > self.NumberOfRarestFeatures:
            freq, MostAbundantRareFeature = self.RareFeaturesHeap[0]
            if freq <= self.FeatureFrequencyThreshold:
                break

            # Remove the most abundant rare feature.
            heapq.heappop(self.RareFeaturesHeap)
            self.RareFeatures.remove(MostAbundantRareFeature)
            
            for II in fuzz_candidates:
                if II.feature_frequency[MostAbundantRareFeature] > 0:
                    del II.feature_frequency[MostAbundantRareFeature]
                    II.NeedsEnergyUpdate = True

        # Add rare feature, handle collisions, and update energy.
        self.RareFeatures.add(feature)
        heapq.heappush(self.RareFeaturesHeap, (0, feature))

        for II in fuzz_candidates:
            del II.feature_frequency[feature]

            # Apply add-one smoothing to this locally undiscovered feature.
            # Zero energy seeds will never be fuzzed and remain zero energy.
            if (II.energy > 0.0):
                II.SumIncidence += 1
                II.energy += math.log(II.SumIncidence) / II.SumIncidence

        self.DistributionNeedsUpdate = True

    # Increment the global frequencies
    def update_coverage_frequency(self, fuzz_candidates, features):
        self.feature_frequency.update(features)
        
        # TODO: Move this somewhere else?
        for II in fuzz_candidates:
            if any(II.feature_frequency[f] > 0 for f in features):
                II.NeedsEnergyUpdate = True
    
    def reset_coverage_frequency(self):
        self.feature_frequency = Counter()

   
