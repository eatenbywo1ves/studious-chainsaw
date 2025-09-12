"""
Simple Random Output Generator
"""

import random
import numpy as np
import time


def generate_randoms():
    print("RANDOM OUTPUT GENERATOR")
    print("=" * 40)

    # Random numbers
    print("\nRANDOM NUMBERS:")
    print("Integers:", [random.randint(1, 100) for _ in range(8)])
    print("Floats:", [round(random.uniform(0, 10), 2) for _ in range(6)])
    print("Normal dist:", np.random.normal(0, 1, 5).round(2))

    # Random text
    print("\nRANDOM TEXT:")
    words = ['quantum', 'neural', 'cosmic', 'digital', 'fractal', 'matrix']
    adjectives = ['amazing', 'brilliant', 'chaotic', 'dynamic', 'elegant']
    sentences = []
    for _ in range(4):
        adj = random.choice(adjectives)
        word = random.choice(words)
        sentences.append(f"The {adj} {word} system operates efficiently.")

    for i, sentence in enumerate(sentences, 1):
        print(f"{i}. {sentence}")

    # Random data
    print("\nRANDOM DATA:")
    data = {
        'temperature': random.randint(15, 35),
        'pressure': round(random.uniform(995, 1025), 1),
        'humidity': random.randint(30, 90),
        'status': random.choice(['active', 'idle', 'processing'])
    }
    print("Weather data:", data)

    # Random sequences
    print("\nRANDOM SEQUENCES:")

    # Random walk
    position = 0
    walk = [position]
    for _ in range(10):
        step = random.choice([-2, -1, 1, 2])
        position += step
        walk.append(position)
    print("Random walk:", walk)

    # Shuffled numbers
    numbers = list(range(1, 16))
    random.shuffle(numbers)
    print("Shuffled 1-15:", numbers)

    # Random matrix
    print("\nRANDOM MATRIX:")
    matrix = np.random.randint(0, 20, (4, 4))
    print(matrix)

    # Random choices
    print("\nRANDOM CHOICES:")
    colors = ['red', 'blue', 'green', 'yellow', 'purple']
    animals = ['cat', 'dog', 'bird', 'fish', 'rabbit']

    print("Colors:", random.sample(colors, 3))
    print("Animals:", [random.choice(animals) for _ in range(5)])
    print("Yes/No/Maybe:",
          [random.choice(['Yes', 'No', 'Maybe']) for _ in range(6)])

    # Random scientific data
    print("\nRANDOM SCIENTIFIC DATA:")
    experiments = {
        'trial_1': [round(random.normalvariate(100, 15), 1)
                    for _ in range(5)],
        'trial_2': [round(random.normalvariate(85, 12), 1)
                    for _ in range(5)],
        'trial_3': [round(random.normalvariate(110, 18), 1)
                    for _ in range(5)]
    }

    for trial, values in experiments.items():
        print(f"{trial}: {values}")

    # Random coordinates
    coords = [(round(random.uniform(-90, 90), 2),
               round(random.uniform(-180, 180), 2)) for _ in range(3)]
    print("Coordinates:", coords)

    # Final random elements
    print("\nFINAL RANDOMS:")
    print("Random seed:", random.randint(1000, 9999))
    print("Random time:", round(time.time() % 1000, 2))
    print("Random boolean:", random.choice([True, False]))
    print("Random hex:",
          ''.join(random.choices('0123456789ABCDEF', k=8)))

    # Random message
    messages = [
        "Randomness achieved successfully!",
        "Chaos theory in action!",
        "Entropy maximized!",
        "Stochastic process complete!",
        "Monte Carlo simulation finished!"
    ]
    print("\nRandom message:", random.choice(messages))
    print("=" * 40)


if __name__ == "__main__":
    generate_randoms()
