from collections import Counter
from random import Random
import math
import logging
import heapq

class InputInfo:
    """Represent an input with additional attributes"""

    def __init__(self, fuzz_input):
        self.U = fuzz_input  # The actual input data.
        # Number of features that this input has and no smaller input has.
        self.NumFeatures = 0
        
        # Stats.
        self.NumExecutedMutations = 0
        self.NumSuccessfullMutations = 0
        self.NeverReduce = False
        self.MayDeleteFile = False
        self.Reduced = False
        self.HasFocusFunction = False
        self.UniqFeatureSet = set()
        # Power schedule.
        self.NeedsEnergyUpdate = False
        self.Energy = 0.0
        self.SumIncidence = 0.0
        self.FeatureFreqs = Counter()
    
    def DeleteFeatureFreq(self, feature):
        """Delete feature and its frequency from FeatureFreqs."""
        del self.FeatureFreqs[feature]

    def UpdateEnergy(self, GlobalNumberOfFeatures):
        """ Assign more energy to a high-entropy seed, i.e., that reveals more
        information about the globally rare features in the neighborhood of the
        seed. Since we do not know the entropy of a seed that has never been
        executed we assign fresh seeds maximum entropy and let candidate.energy approach
        the true entropy from above. If ScalePerExecTime is true, the computed
        entropy is scaled based on how fast this input executes compared to the
        average execution time of inputs. The faster an input executes, the more
        energy gets assigned to the input.
        """
        self.Energy = 0.0
        self.SumIncidence = 0.0

        # Apply add-one smoothing to locally discovered features.
        for freq in self.FeatureFreqs.values():
            LocalIncidence = freq + 1
            self.Energy -= LocalIncidence * math.log(LocalIncidence)
            self.SumIncidence += LocalIncidence

        # Apply add-one smoothing to locally undiscovered features.
        #   PreciseEnergy -= 0; # since log(1.0) == 0)
        self.SumIncidence += GlobalNumberOfFeatures - len(self.FeatureFreqs)

        # Add a single locally abundant feature apply add-one smoothing.
        AbdIncidence = self.NumExecutedMutations + 1
        self.Energy -= AbdIncidence * math.log(AbdIncidence)
        self.SumIncidence += AbdIncidence

        # Normalize.
        if self.SumIncidence != 0:
            self.Energy = self.Energy / self.SumIncidence + math.log(self.SumIncidence)
    
    def UpdateFeatureFrequency(self, feature):
        """Increment the frequency of the feature Idx."""
        self.NeedsEnergyUpdate = True
        self.FeatureFreqs[feature] += 1
    

class InputCorpus:
    kFeatureSetSize = 1 << 21
    kMaxMutationFactor = 20
    kSparseEnergyUpdates = 100

    def __init__(self,
                 randomizer_seed, 
                 FeatureFrequencyThreshold, 
                 NumberOfRarestFeatures):
        self.random = Random(randomizer_seed)

        # EntropicOptions
        self.NumberOfRarestFeatures = NumberOfRarestFeatures
        self.FeatureFrequencyThreshold = FeatureFrequencyThreshold

        self.NumExecutedMutations = 0

        #---------------------- private ----------------------
        # Corpus distribution
        self.Weights = {}

        self.Inputs = []
        self.NumAddedFeatures = 0
        self.NumUpdatedFeatures = 0
        self.InputSizesPerFeature = [0]*self.kFeatureSetSize
        self.SmallestElementPerFeature = [0]*self.kFeatureSetSize

        self.DistributionNeedsUpdate = True
        self.FreqOfMostAbundantRareFeature = 0
        self.GlobalFeatureFreqs = Counter()
        self.RareFeatures = set()

    def size(self):
        return len(self.Inputs)
    
    def IncrementNumExecutedMutations(self):
        self.NumExecutedMutations += 1
    
    def empty(self):
        return len(self.Inputs) == 0
    
    def __getitem__(self, key):
        return self.Inputs[key]
    
    def AddToCorpus(self, fuzz_input, NumFeatures, FeatureSet):
        II = InputInfo(fuzz_input)
        self.Inputs.append(II)
        II.NumFeatures = NumFeatures
        II.UniqueFeatureSet = FeatureSet
        # Assign maximal energy to the new seed.
        II.Energy = 1.0 if len(self.RareFeatures) == 0 else math.log(len(self.RareFeatures))
        II.SumIncidence = len(self.RareFeatures)
        II.NeedsEnergyUpdate = False
        self.DistributionNeedsUpdate = True
        return II

    def ChooseUnitToMutate(self):
        """Choose weighted by normalized energy."""
        logger = logging.getLogger(__name__)
        self.UpdateCorpusDistribution()
        II = self.random.choices(
                            self.Inputs,
                            weights=(self.Weights[II] for II in self.Inputs)
                            )[0]
        logger.debug(f'Chose fuzz-candidate with fuzz-input-hash {II.U.hexdigest}')
        return II

    def AddRareFeature(self, feature):
        # Maintain *at least* NumberOfRarestFeatures many rare features
        # and all features with a frequency below ConsideredRare.
        # Remove all other features.

        if len(self.RareFeatures) > self.NumberOfRarestFeatures and \
            self.FreqOfMostAbundantRareFeature > self.FeatureFrequencyThreshold:

            extras = heapq.nlargest(len(self.RareFeatures) > self.NumberOfRarestFeatures,
                                    self.RareFeatures,
                                    key=lambda f: self.GlobalFeatureFreqs[f])

            while len(extras) > 0 and \
                    self.FreqOfMostAbundantRareFeature > self.FeatureFrequencyThreshold:
                # Remove most abundant rare feature.
                MostAbundantRareFeature = heapq.heappop(extras)
                self.RareFeatures.remove(MostAbundantRareFeature)
                for II in self.Inputs:
                    if II.FeatureFreqs[MostAbundantRareFeature] > 0:
                        del II.FeatureFreqs[MostAbundantRareFeature]
                        II.NeedsEnergyUpdate = True

                # Set 2nd most abundant as the new most abundant feature count.
                self.FreqOfMostAbundantRareFeature = self.GlobalFeatureFreqs[extras[0]]

        # Add rare feature, handle collisions, and update energy.
        self.RareFeatures.add(feature)
        self.GlobalFeatureFreqs[feature] = 0

        for II in self.Inputs:
            del II.FeatureFreqs[feature]

            # Apply add-one smoothing to this locally undiscovered feature.
            # Zero energy seeds will never be fuzzed and remain zero energy.
            if (II.Energy > 0.0):
                II.SumIncidence += 1
                II.Energy += math.log(II.SumIncidence) / II.SumIncidence

        self.DistributionNeedsUpdate = True

    def AddFeature(self, feature):
        if feature in self.RareFeatures:
            return False
        else:
            self.NumAddedFeatures += 1
            self.AddRareFeature(feature)
            self.NumUpdatedFeatures += 1
            return True
        
    # Increment frequency of features globally and locally.
    def UpdateFeatureFrequency(self, II, feature):

        # Saturated increment.
        if self.GlobalFeatureFreqs[feature] == 0xFFFF:
            return
        Freq = self.GlobalFeatureFreqs[feature]
        self.GlobalFeatureFreqs[feature] += 1

        # Skip if abundant
        if Freq > self.FreqOfMostAbundantRareFeature or feature not in self.RareFeatures:
            return

        # Update global frequencies.
        if (Freq == self.FreqOfMostAbundantRareFeature):
            self.FreqOfMostAbundantRareFeature += 1

        # Update local frequencies.
        if II:
            II.UpdateFeatureFrequency(feature)   

    def NumFeatures(self):
        return self.NumAddedFeatures

    def NumFeatureUpdates(self):
        return self.NumUpdatedFeatures

    #---------------------- private ----------------------

    def UpdateCorpusDistribution(self):
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

        N = len(self.Inputs)

        VanillaSchedule = True
        for II in self.Inputs:
            if (II.NeedsEnergyUpdate and II.Energy != 0.0):
                II.NeedsEnergyUpdate = False
                II.UpdateEnergy(len(self.RareFeatures))

        for II in self.Inputs:
            if II.NumFeatures == 0:
                # If the seed doesn't represent any features, assign zero energy.
                self.Weights[II] = 0.
            elif (II.NumExecutedMutations / self.kMaxMutationFactor >
                    self.NumExecutedMutations / len(self.Inputs)):
                # If the seed was fuzzed a lot more than average, assign zero energy.
                self.Weights[II] = 0.
            else:
                # Otherwise, simply assign the computed energy.
                self.Weights[II] = II.Energy

            # If energy for all seeds is zero, fall back to vanilla schedule.
            if (self.Weights[II] > 0.0):
                VanillaSchedule = False

        if VanillaSchedule:
            for i, II in enumerate(self.Inputs):
                self.Weights[II] = (i + 1) if II.NumFeatures > 0 \
                                    else 0.