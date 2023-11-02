import random
class Randomizer:


    def Generate(self, n):
        resArr = []
        step = random.randint(1, pow (2,15))

        resArr.append(step)
        for i in range(1, n):
            resArr.append(((8 * resArr[i - 1]) + 8) % pow (2,15)-1)

        return  resArr