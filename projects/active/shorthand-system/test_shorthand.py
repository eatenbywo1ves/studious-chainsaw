"""
Quick test of the shorthand auto-response system
"""

from shorthand_autoresponder import ShorthandEngine, ResponseContext
from shorthand_libraries import load_library

# Initialize engine
engine = ShorthandEngine()

# Load some libraries
load_library("it_support", engine)
load_library("developer", engine)

print("="*60)
print("SHORTHAND AUTO-RESPONSE SYSTEM - QUICK TEST")
print("="*60)

# Test cases
test_cases = [
    ("gm everyone!", "Greeting"),
    ("ty for your help", "Acknowledgment"),
    ("Please check asap", "Email"),
    ("I'll esc1 this issue", "IT Support"),
    ("lgtm! Ship it!", "Code Review"),
    ("Meeting at eod", "Business"),
    ("brb in 5", "Chat"),
]

print("\nTesting Text Expansions:")
print("-" * 40)

for text, description in test_cases:
    expanded = engine.expand(text)
    if expanded != text:
        print(f"✓ [{description}]")
        print(f"  Input:  '{text}'")
        print(f"  Output: '{expanded}'")
    else:
        print(f"✗ [{description}] No expansion for '{text}'")
    print()

# Test statistics
stats = engine.get_statistics()
print("-" * 40)
print(f"Total rules loaded: {stats['total_rules']}")
print(f"Categories: {list(stats['categories'].keys())}")

print("\n✅ Test completed successfully!")