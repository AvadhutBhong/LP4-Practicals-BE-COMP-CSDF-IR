import re
from collections import defaultdict

def mapper(text):
    
    mapped = []
    for line in text.splitlines():
        line = line.strip().lower()
        for char in line:
            if char.isalpha():  
                mapped.append((char, 1))
    return mapped


def reducer(mapped_data):
    
    reduced = defaultdict(int)
    for key, value in mapped_data:
        reduced[key] += value
    return reduced



text = """
This is a sample text file for testing the Map reduce code. It maps the characters and reduces to get frequency of each character
"""


mapped_data = mapper(text)
reduced_data = reducer(mapped_data)

for char in sorted(reduced_data.keys()):
    print(f"{char}\t{reduced_data[char]}")
