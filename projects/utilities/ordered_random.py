"""
Ordered Random Output Generator
Displays random results in structured, organized format
"""

import random
import numpy as np
import time
from collections import OrderedDict


def generate_ordered_random_outputs():
    """Generate random outputs and display them in ordered format"""

    # Set seed for reproducible demo (remove for true randomness)
    random.seed(42)
    np.random.seed(42)

    print("ORDERED RANDOM OUTPUT DISPLAY")
    print("=" * 60)

    # Create ordered dictionary to maintain structure
    results = OrderedDict()

    # 1. NUMERICAL DATA (ordered by type)
    print("\n1. NUMERICAL DATA")
    print("-" * 30)

    numerical_data = OrderedDict([
        ('integers_1_to_10',
         sorted([random.randint(1, 100) for _ in range(10)])),
        ('floats_0_to_1',
         sorted([round(random.uniform(0, 1), 3) for _ in range(8)])),
        ('normal_distribution',
         sorted(np.random.normal(0, 1, 6).round(2))),
        ('exponential_values',
         sorted([round(2**i + random.uniform(-0.5, 0.5), 2)
                 for i in range(5)])),
        ('fibonacci_variant', None)  # Will be calculated
    ])

    # Generate ordered Fibonacci variant
    fib = [1, 1]
    for i in range(6):
        fib.append(fib[-1] + fib[-2])
    numerical_data['fibonacci_variant'] = fib

    for key, values in numerical_data.items():
        print(f"{key:20}: {values}")

    results['numerical'] = numerical_data

    # 2. TEXT DATA (ordered alphabetically)
    print("\n2. TEXT DATA")
    print("-" * 30)

    # Generate words and sort them
    syllables = ['ba', 'ca', 'da', 'fa', 'ga', 'ha', 'ja', 'ka', 'la', 'ma']
    random_words = []
    for _ in range(10):
        word = ''.join(random.choices(syllables, k=random.randint(2, 3)))
        random_words.append(word)

    text_data = OrderedDict([
        ('sorted_random_words', sorted(random_words)),
        ('alphabetic_strings',
         sorted([''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))
                 for _ in range(6)])),
        ('ordered_sentences', [])  # Will be filled
    ])

    # Generate structured sentences
    subjects = sorted(['Algorithm', 'Database', 'Network',
                       'Program', 'System'])
    verbs = sorted(['analyzes', 'computes', 'processes',
                    'executes', 'optimizes'])
    objects = sorted(['data structures', 'neural networks',
                      'quantum states', 'cloud resources',
                      'machine learning models'])

    sentences = []
    for i in range(5):
        sentence = f"{subjects[i]} {verbs[i]} {objects[i]}."
        sentences.append(sentence)

    text_data['ordered_sentences'] = sentences

    for key, values in text_data.items():
        print(f"{key:20}: {values}")

    results['text'] = text_data

    # 3. STRUCTURED DATA (ordered by hierarchy)
    print("\n3. STRUCTURED DATA")
    print("-" * 30)

    structured_data = OrderedDict([
        ('level_a', OrderedDict([
            ('category_1',
             sorted([random.randint(10, 99) for _ in range(4)])),
            ('category_2',
             sorted([random.randint(100, 999) for _ in range(4)])),
            ('category_3',
             sorted([random.randint(1000, 9999) for _ in range(4)]))
        ])),
        ('level_b', OrderedDict([
            ('alpha_values',
             sorted([round(random.uniform(0, 10), 2) for _ in range(5)])),
            ('beta_values',
             sorted([round(random.uniform(10, 20), 2) for _ in range(5)])),
            ('gamma_values',
             sorted([round(random.uniform(20, 30), 2) for _ in range(5)]))
        ])),
        ('level_c', OrderedDict([
            ('coordinates',
             sorted([(round(random.uniform(-90, 90), 2),
                      round(random.uniform(-180, 180), 2))
                     for _ in range(4)])),
            ('timestamps',
             sorted([round(time.time() + random.randint(-1000, 1000), 2)
                     for _ in range(4)])),
            ('identifiers',
             sorted([f"ID_{random.randint(1000, 9999)}"
                     for _ in range(4)]))
        ]))
    ])

    for level_key, level_data in structured_data.items():
        print(f"\n{level_key.upper()}:")
        for category, values in level_data.items():
            print(f"  {category:15}: {values}")

    results['structured'] = structured_data

    # 4. MATRIX DATA (ordered by dimensions)
    print("\n4. MATRIX DATA")
    print("-" * 30)

    matrices = OrderedDict()

    # Generate matrices of increasing size
    for size in [2, 3, 4]:
        matrix_name = f"matrix_{size}x{size}"
        matrix = np.random.randint(1, 20, (size, size))
        # Sort each row for ordered display
        for i in range(size):
            matrix[i] = np.sort(matrix[i])
        matrices[matrix_name] = matrix

    for name, matrix in matrices.items():
        print(f"\n{name}:")
        for row in matrix:
            print(f"  {row}")

    results['matrices'] = matrices

    # 5. SCIENTIFIC DATA (ordered by measurement type)
    print("\n5. SCIENTIFIC DATA")
    print("-" * 30)

    scientific_data = OrderedDict([
        ('experiment_series_a', OrderedDict([
            ('temperature_celsius',
             sorted([round(random.normalvariate(25, 3), 1)
                     for _ in range(8)])),
            ('pressure_kpa',
             sorted([round(random.normalvariate(101.3, 2), 2)
                     for _ in range(8)])),
            ('humidity_percent',
             sorted([round(random.normalvariate(60, 15), 1)
                     for _ in range(8)]))
        ])),
        ('experiment_series_b', OrderedDict([
            ('ph_levels',
             sorted([round(random.uniform(6.0, 8.5), 2)
                     for _ in range(6)])),
            ('conductivity_ms',
             sorted([round(random.uniform(0.1, 2.5), 3)
                     for _ in range(6)])),
            ('dissolved_oxygen_ppm',
             sorted([round(random.uniform(5, 12), 2)
                     for _ in range(6)]))
        ])),
        ('experiment_series_c', OrderedDict([
            ('voltage_readings',
             sorted([round(random.uniform(1.0, 5.0), 2)
                     for _ in range(7)])),
            ('current_ma',
             sorted([round(random.uniform(10, 100), 1)
                     for _ in range(7)])),
            ('resistance_ohms',
             sorted([round(random.uniform(100, 1000), 0)
                     for _ in range(7)]))
        ]))
    ])

    for series, measurements in scientific_data.items():
        print(f"\n{series.replace('_', ' ').title()}:")
        for measurement, values in measurements.items():
            print(f"  {measurement:20}: {values}")

    results['scientific'] = scientific_data

    # 6. STATISTICAL SUMMARY (ordered by statistic type)
    print("\n6. STATISTICAL SUMMARY")
    print("-" * 30)

    # Generate sample data for statistics
    sample_data = [random.normalvariate(100, 15) for _ in range(50)]

    statistics = OrderedDict([
        ('count', len(sample_data)),
        ('mean', round(np.mean(sample_data), 2)),
        ('median', round(np.median(sample_data), 2)),
        ('std_deviation', round(np.std(sample_data), 2)),
        ('minimum', round(min(sample_data), 2)),
        ('maximum', round(max(sample_data), 2)),
        ('range', round(max(sample_data) - min(sample_data), 2)),
        ('variance', round(np.var(sample_data), 2))
    ])

    for stat_name, stat_value in statistics.items():
        print(f"{stat_name:15}: {stat_value}")

    results['statistics'] = statistics

    # 7. FINAL ORDERED SUMMARY
    print("\n" + "=" * 60)
    print("ORDERED OUTPUT SUMMARY")
    print("=" * 60)

    summary = OrderedDict([
        ('total_categories', len(results)),
        ('numerical_items', len(results['numerical'])),
        ('text_items', len(results['text'])),
        ('structured_levels', len(results['structured'])),
        ('matrix_count', len(results['matrices'])),
        ('scientific_series', len(results['scientific'])),
        ('statistical_measures', len(results['statistics'])),
        ('generation_timestamp', time.strftime('%Y-%m-%d %H:%M:%S')),
        ('total_data_points', sum([
            sum(len(v) if isinstance(v, (list, tuple)) else 1
                for v in results['numerical'].values() if v is not None),
            sum(len(v) if isinstance(v, (list, tuple)) else 1
                for v in results['text'].values()),
            sum(matrix.size for matrix in results['matrices'].values()),
            len(results['statistics'])
        ]))
    ])

    for key, value in summary.items():
        print(f"{key:25}: {value}")

    print("\nAll outputs displayed in ordered, structured format.")
    print("Categories: Numerical → Text → Structured → Matrix → "
          "Scientific → Statistical")

    return results


if __name__ == "__main__":
    ordered_results = generate_ordered_random_outputs()
