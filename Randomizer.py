import random
class Randomizer:


    def Generate(self, n):
        resArr = []
        step = 64

        resArr.append(step)
        randomM = random.randint(1, pow (2,15));
        for i in range(1, n):
            resArr.append(((8 * resArr[i - 1]) + 8) % randomM-1)

        return  resArr