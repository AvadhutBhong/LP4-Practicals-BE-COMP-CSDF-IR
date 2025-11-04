from collections import defaultdict
from typing import List, Dict, Tuple
import string
from pathlib import Path

# Mapper function: Responsible for reading text input and emitting intermediate (key, value) pairs
def mapper(text: str) -> List[Tuple[str, int]]:
    """
    Map phase: Convert text to (character, count) pairs.
    Each alphabetic character (case-insensitive) is mapped to value 1.
    """
    mapped = []  # Will store tuples like ('a', 1), ('b', 1), etc.

    # Split input text into lines to process line by line
    for line in text.splitlines():
        # Convert line to lowercase for case-insensitive counting
        line = line.strip().lower()
        # Iterate over each character in the line
        for char in line:
            # Check if the character is an alphabetic letter (ignores digits, punctuation, etc.)
            if char in string.ascii_letters:
                # Emit a key-value pair (character, 1)
                mapped.append((char, 1))
    # Return list of all intermediate (key, value) pairs
    return mapped


# Reducer function: Combines all mapped data and aggregates counts for each key (character)
def reducer(mapped_data: List[Tuple[str, int]]) -> Dict[str, int]:
    """
    Reduce phase: Aggregate counts for each alphabetic character.
    Equivalent to the "shuffle and reduce" step in Hadoop MapReduce.
    """
    reduced = defaultdict(int)
    for key, value in mapped_data:
        reduced[key] += value
    return dict(reduced)


# Helper function to display results neatly in tabular form
def print_results(reduced_data: Dict[str, int], show_total: bool = True) -> None:
    """Print character frequencies without percentages."""
    print("\nCharacter Frequency Analysis")
    print("-" * 25)
    print("Char | Count")
    print("-" * 25)
    
    for char in sorted(reduced_data.keys()):
        count = reduced_data[char]
        print(f" {char}   |  {count:4d}")
    
    if show_total:
        print("-" * 25)
        print(f"Total characters: {sum(reduced_data.values())}")


# Function to handle file input (to simulate real dataset processing)
def process_file(filepath: str) -> Dict[str, int]:
    """
    Reads a file and processes it through MapReduce pipeline.
    Handles file reading and exceptions.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            text = f.read()
        mapped_data = mapper(text)
        return reducer(mapped_data)
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found")
        return {}
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        return {}


def main():
    # Sample text used for demonstration
    sample_text = """
    The quick brown fox jumps over the lazy dog!
    This pangram contains every letter of the English alphabet.
    12345 ... !@#$ ... Testing special characters too.
    """
    
    print("Processing sample text...")
    mapped = mapper(sample_text)
    reduced = reducer(mapped)
    print_results(reduced)
    
    # Optional: Demonstrate file-based processing if file exists
    filepath = "sample.txt"
    if Path(filepath).exists():
        print(f"\nProcessing file: {filepath}")
        file_results = process_file(filepath)
        print_results(file_results)


# Main program entry point
if __name__ == "__main__":
    main()



"""
============================ THEORY: MAP-REDUCE CHARACTER COUNT ============================

👉 Approach and Working:
This program implements a simplified **MapReduce** framework in Python to count the frequency of
each alphabetic character (case-insensitive) in a given text dataset. It mimics the distributed
MapReduce model used in **Hadoop** or **Spark**, but runs locally for demonstration purposes.

The goal is to read text data, map each letter to a count of 1, and then reduce (aggregate)
the counts of identical keys (letters). Non-alphabetic characters like digits, punctuation,
and spaces are ignored.

----------------------------------
👉 Step-by-Step Flow:

1. **Input Splitting:**
   - The input dataset (string or file) is divided into smaller units (lines).
   - This simulates Hadoop’s data blocks being processed by individual mappers.

2. **Map Phase:**
   - Each line is processed by the `mapper()` function.
   - Every alphabetic character (A–Z, a–z) is converted to lowercase to ensure
     case-insensitivity.
   - Each valid character emits a pair: `(character, 1)`.

   Example:
   Input line: "AbC!"
   Output from mapper: `[('a', 1), ('b', 1), ('c', 1)]`

3. **Shuffle and Sort Phase (Conceptual Step):**
   - In a real MapReduce system, all emitted pairs are grouped by key (character).
   - This ensures all counts for a given character go to the same reducer.
   - In this Python implementation, we simulate this grouping using a dictionary.

4. **Reduce Phase:**
   - The `reducer()` function aggregates all counts for each character.
   - For example: for key `'a'` with intermediate values [1, 1, 1, 1], total = 4.
   - This produces the final frequency count per alphabetic character.

5. **Output Phase:**
   - The results are displayed in a formatted table showing:
     - Character
     - Count

----------------------------------
👉 Example Execution:

Input text:
"The quick brown fox"

Mapper output:
[('t',1), ('h',1), ('e',1), ('q',1), ('u',1), ('i',1), ('c',1), ('k',1), ('b',1),
 ('r',1), ('o',1), ('w',1), ('n',1), ('f',1), ('o',1), ('x',1)]

Reducer output:
{
 'a':0, 'b':1, 'c':1, 'e':1, 'f':1, 'h':1, 'i':1,
 'k':1, 'n':1, 'o':2, 'q':1, 'r':1, 't':1, 'u':1, 'w':1, 'x':1
}

----------------------------------
👉 Key Concepts in MapReduce:

1. **Mapper:**
   - Processes input data and outputs (key, value) pairs.
   - Works independently on chunks of data in parallel in distributed systems.

2. **Reducer:**
   - Receives all values for the same key from different mappers.
   - Aggregates or combines them to produce the final result.

3. **Shuffle and Sort:**
   - The intermediate phase that groups values by their key.
   - Ensures that all related data reaches the same reducer.

4. **Combiner (Optional Optimization):**
   - Local reducer used after the mapper to reduce data volume before shuffling.

----------------------------------
👉 Case-Insensitivity and Filtering:

- Every line is converted to lowercase → `line.lower()`
- Only alphabetic characters (a–z) are included → `if char in string.ascii_letters`
- Ensures:
  - 'A' and 'a' are counted together.
  - Numbers, spaces, and symbols are ignored.

----------------------------------
👉 Advantages of MapReduce:

- Scalable and fault-tolerant for large datasets.
- Simple key-value abstraction for parallel computation.
- Suitable for distributed data aggregation.

----------------------------------
👉 Limitations:

- Not suitable for small datasets due to overhead.
- Data shuffling between nodes can be expensive.
- Not ideal for iterative or real-time processing.

----------------------------------
👉 Real-World Applications:

- Character or word count in documents.
- Log file analysis and indexing.
- Search engine data processing.
- Text mining and data aggregation.

----------------------------------
👉 How to Run:

1. Save this file as `mapreduce_char_count.py`
2. Run in terminal:  
   `python mapreduce_char_count.py`
3. Optionally, place a `sample.txt` file in the same directory to analyze.

----------------------------------
👉 Summary:

This program demonstrates the **core MapReduce workflow** — mapping, shuffling, and reducing —
to count the occurrence of alphabetic characters in a text dataset. It’s a fundamental building
block for understanding distributed data processing frameworks such as Hadoop and Spark.

====================================================================================
"""
