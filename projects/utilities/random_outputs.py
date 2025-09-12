"""
Random Output Generator
Creating various types of random data and outputs
"""

import numpy as np
import random
import string
import time


def generate_random_numbers():
    """Generate various random numerical outputs"""

    print("🎲 RANDOM NUMBERS")
    print("-" * 30)

    # Basic random integers
    random_ints = [random.randint(1, 100) for _ in range(10)]
    print(f"Random integers (1-100): {random_ints}")

    # Random floats
    random_floats = [round(random.uniform(-10, 10), 3) for _ in range(8)]
    print(f"Random floats (-10 to 10): {random_floats}")

    # NumPy random arrays
    normal_array = np.random.normal(0, 1, 5)
    print(f"Normal distribution: {normal_array.round(3)}")

    # Random matrix
    matrix = np.random.randint(0, 50, (3, 4))
    print(f"Random 3x4 matrix:\n{matrix}")

    return {
        'integers': random_ints,
        'floats': random_floats,
        'normal': normal_array.tolist(),
        'matrix': matrix.tolist()
    }


def generate_random_text():
    """Generate random text outputs"""

    print("\n📝 RANDOM TEXT")
    print("-" * 30)

    # Random words
    syllables = ['ba', 'ca', 'da', 'fa', 'ga', 'ha', 'ja', 'ka', 'la', 'ma',
                 'na', 'pa', 'ra', 'sa', 'ta', 'va', 'wa', 'ya', 'za']
    random_words = []
    for _ in range(8):
        word_length = random.randint(2, 4)
        word = ''.join(random.choices(syllables, k=word_length))
        random_words.append(word)

    print(f"Random words: {' '.join(random_words)}")

    # Random strings
    random_string = ''.join(random.choices(string.ascii_letters +
                                           string.digits, k=15))
    print(f"Random string: {random_string}")

    # Random sentences
    subjects = ["The cat", "A robot", "My friend", "The ocean",
                "A star", "The algorithm"]
    verbs = ["jumps", "calculates", "explores", "shimmers",
             "computes", "dances"]
    objects = ["over mountains", "through data", "in space",
               "with precision", "beyond limits", "into chaos"]

    sentences = []
    for _ in range(5):
        sentence = (f"{random.choice(subjects)} {random.choice(verbs)} "
                    f"{random.choice(objects)}.")
        sentences.append(sentence)

    print("Random sentences:")
    for sentence in sentences:
        print(f"  • {sentence}")

    return {
        'words': random_words,
        'string': random_string,
        'sentences': sentences
    }


def generate_random_data_structures():
    """Generate random data structures"""

    print("\n🗂️  RANDOM DATA STRUCTURES")
    print("-" * 30)

    # Random dictionary
    keys = ['alpha', 'beta', 'gamma', 'delta', 'epsilon']
    random_dict = {key: random.randint(10, 1000)
                   for key in random.sample(keys, 3)}
    print(f"Random dictionary: {random_dict}")

    # Random list of mixed types
    random_list = [
        random.randint(1, 100),
        round(random.uniform(0, 1), 3),
        random.choice(['apple', 'banana', 'cherry']),
        random.choice([True, False]),
        ''.join(random.choices(string.ascii_uppercase, k=3))
    ]
    print(f"Mixed random list: {random_list}")

    # Random nested structure
    nested_data = {
        'level1': {
            'numbers': [random.randint(1, 10) for _ in range(4)],
            'level2': {
                'random_key': random.choice(['value1', 'value2', 'value3']),
                'timestamp': time.time(),
                'coordinates': (random.uniform(-90, 90),
                                random.uniform(-180, 180))
            }
        },
        'metadata': {
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'random_id': random.randint(10000, 99999)
        }
    }

    print(f"Nested structure: {nested_data}")

    return {
        'dictionary': random_dict,
        'mixed_list': random_list,
        'nested': nested_data
    }


def generate_random_sequences():
    """Generate random sequences and patterns"""

    print("\n🔢 RANDOM SEQUENCES")
    print("-" * 30)

    # Fibonacci-like with random starts
    a, b = random.randint(1, 5), random.randint(1, 5)
    fibonacci_variant = [a, b]
    for _ in range(8):
        next_val = fibonacci_variant[-1] + fibonacci_variant[-2]
        fibonacci_variant.append(next_val)

    print(f"Random Fibonacci variant: {fibonacci_variant}")

    # Random walk
    position = 0
    random_walk = [position]
    for _ in range(20):
        step = random.choice([-1, 1])
        position += step
        random_walk.append(position)

    print(f"Random walk: {random_walk}")

    # Random geometric series
    base = random.uniform(1.1, 2.0)
    geometric = [round(base**i, 2) for i in range(6)]
    print(f"Random geometric series (base={base:.2f}): {geometric}")

    # Shuffled sequence
    ordered = list(range(1, 16))
    shuffled = ordered.copy()
    random.shuffle(shuffled)
    print(f"Shuffled 1-15: {shuffled}")

    return {
        'fibonacci_variant': fibonacci_variant,
        'random_walk': random_walk,
        'geometric': geometric,
        'shuffled': shuffled
    }


def generate_random_choices():
    """Generate random choices and selections"""

    print("\n🎯 RANDOM CHOICES")
    print("-" * 30)

    # Random colors
    colors = ['red', 'blue', 'green', 'yellow', 'purple', 'orange',
              'pink', 'cyan', 'magenta', 'lime']
    selected_colors = random.sample(colors, 4)
    print(f"Random color selection: {selected_colors}")

    # Random animals
    animals = ['elephant', 'tiger', 'dolphin', 'eagle', 'penguin',
               'kangaroo', 'octopus', 'giraffe']
    random_animals = [random.choice(animals) for _ in range(6)]
    print(f"Random animals: {random_animals}")

    # Random yes/no decisions
    decisions = [random.choice(['Yes', 'No', 'Maybe']) for _ in range(8)]
    print(f"Random decisions: {decisions}")

    # Weighted random choice
    items = ['Common', 'Uncommon', 'Rare', 'Epic', 'Legendary']
    weights = [50, 30, 15, 4, 1]
    weighted_choices = random.choices(items, weights=weights, k=10)
    print(f"Weighted random choices: {weighted_choices}")

    return {
        'colors': selected_colors,
        'animals': random_animals,
        'decisions': decisions,
        'weighted': weighted_choices
    }


def generate_random_scientific_data():
    """Generate random scientific-looking data"""

    print("\n🔬 RANDOM SCIENTIFIC DATA")
    print("-" * 30)

    # Fake experimental data
    experiment_data = {
        'temperature': [round(random.normalvariate(25, 3), 1)
                        for _ in range(10)],
        'pressure': [round(random.normalvariate(101.3, 0.5), 2)
                     for _ in range(10)],
        'ph_level': [round(random.uniform(6.5, 8.5), 2)
                     for _ in range(10)]
    }

    print("Experimental measurements:")
    for parameter, values in experiment_data.items():
        print(f"  {parameter}: {values}")

    # Random chemical formula
    elements = ['H', 'C', 'N', 'O', 'P', 'S', 'Cl', 'Na', 'K', 'Ca']
    formula_parts = []
    for _ in range(random.randint(2, 4)):
        element = random.choice(elements)
        count = random.randint(1, 5)
        if count == 1:
            formula_parts.append(element)
        else:
            formula_parts.append(f"{element}{count}")

    chemical_formula = ''.join(formula_parts)
    print(f"Random chemical formula: {chemical_formula}")

    # Random coordinates (latitude/longitude)
    coordinates = [
        (round(random.uniform(-90, 90), 4),
         round(random.uniform(-180, 180), 4))
        for _ in range(5)
    ]
    print(f"Random coordinates: {coordinates}")

    return {
        'experiment': experiment_data,
        'formula': chemical_formula,
        'coordinates': coordinates
    }


def main():
    """Generate all types of random outputs"""

    print("🎲 RANDOM OUTPUT GENERATOR")
    print("=" * 50)

    # Set random seed for some reproducibility in demo
    # (Remove this to get truly random outputs each time)
    random.seed(int(time.time()) % 1000)
    np.random.seed(int(time.time()) % 1000)

    # Generate all types
    all_outputs = {
        'numbers': generate_random_numbers(),
        'text': generate_random_text(),
        'data_structures': generate_random_data_structures(),
        'sequences': generate_random_sequences(),
        'choices': generate_random_choices(),
        'scientific': generate_random_scientific_data()
    }

    print("=" * 50)
    print("🎯 RANDOM GENERATION COMPLETE!")
    print("=" * 50)
    print(f"Generated {sum(len(str(v)) for v in all_outputs.values())} "
          f"characters of random data")
    print("Categories: Numbers, Text, Data Structures, Sequences, "
          "Choices, Scientific")

    # Final random message
    messages = [
        "Randomness is the spice of computation!",
        "Chaos theory in action!",
        "Entropy maximized successfully!",
        "Random walk completed!",
        "Stochastic process terminated!",
        "Monte Carlo simulation finished!"
    ]

    print(f"\n🎲 Random closing: {random.choice(messages)}")

    return all_outputs


if __name__ == "__main__":
    results = main()
