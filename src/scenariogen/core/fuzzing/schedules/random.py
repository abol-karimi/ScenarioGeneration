from random import Random


class RandomSchedule:
    def __init__(self, randomizer_seed):
        self.random = Random(randomizer_seed)

    def get_state(self):
        return self.random.getstate()
    
    def set_state(self, state):
        self.random.setstate(state)

    def choose(self, population):
        fuzz_candidate = self.random.choice(population)
        print(f'Chose fuzz-candidate with fuzz-input-hash {fuzz_candidate.fuzz_input.hexdigest}')
        return fuzz_candidate