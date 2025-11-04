import math
import string
import sys
from collections import Counter
from typing import Dict, List

def read_file(filename: str) -> str:
    """Read and return the full text of a file."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except IOError as e:
        print(f"Error reading file {filename}: {str(e)}")
        sys.exit(1)

# Create a translation table to remove punctuation and convert uppercase to lowercase.
# str.maketrans() maps each punctuation and uppercase character to a lowercase or space.
TRANS_TABLE = str.maketrans(
    string.punctuation + string.ascii_uppercase,  # all punctuation + uppercase letters
    " " * len(string.punctuation) + string.ascii_lowercase  # map punctuation to space and uppercase → lowercase
)

def get_words_from_text(text: str) -> List[str]:
    """Convert text into a clean list of lowercase words."""
    # Replace punctuation with spaces and convert all text to lowercase
    text = text.translate(TRANS_TABLE)
    # Split into words (splitting by whitespace)
    words = text.split()
    # Filter out any empty strings (if multiple spaces existed)
    return [word for word in words if word]

def count_frequency(word_list: List[str]) -> Dict[str, int]:
    """Count how many times each word appears using Python's Counter."""
    return Counter(word_list)

def word_frequencies_for_file(filename: str) -> Dict[str, int]:
    """Read file, extract words, count frequencies, and print summary."""
    text = read_file(filename)
    words = get_words_from_text(text)
    frequencies = count_frequency(words)
    
    print(f"\nAnalysis of {filename}:")
    print(f"Total words: {len(words)}")
    print(f"Unique words: {len(frequencies)}")
    print(f"Most common words: {', '.join(w for w, _ in frequencies.most_common(5))}")
    
    return frequencies

def cosine_similarity(d1: Dict[str, int], d2: Dict[str, int]) -> float:
    """
    Compute cosine similarity between two word frequency dictionaries.
    Formula:
        cos(θ) = (A·B) / (||A|| * ||B||)
    where A·B is the dot product of the two frequency vectors.
    """
    # dot_product = sum of (word frequency in doc1 * frequency in doc2) for all common words
    dot_product = sum(d1.get(word, 0) * d2.get(word, 0) for word in set(d1) | set(d2))
    
    # Compute the magnitude (Euclidean norm) of each frequency vector
    norm1 = math.sqrt(sum(count * count for count in d1.values()))
    norm2 = math.sqrt(sum(count * count for count in d2.values()))
    
    # Avoid division by zero
    if norm1 == 0 or norm2 == 0:
        return 0.0

    # Return cosine similarity (value between 0 and 1)
    return dot_product / (norm1 * norm2)

def document_similarity(file1: str, file2: str) -> None:
    """Compare two text files and print similarity report."""
    print("\nComputing document similarity...")
    
    # Step 1: Compute word frequency for both documents
    freq1 = word_frequencies_for_file(file1)
    freq2 = word_frequencies_for_file(file2)
    
    # Step 2: Compute cosine similarity between their frequency vectors
    similarity = cosine_similarity(freq1, freq2)
    
    # Step 3: Derive the angle between documents (in radians and degrees)
    angle = math.acos(min(1.0, similarity))  # min(1.0, ...) avoids floating point domain errors
    
    print("\nSimilarity Metrics:")
    print(f"Cosine Similarity: {similarity:.4f}")
    print(f"Angle between documents: {angle:.4f} radians ({math.degrees(angle):.2f} degrees)")
    
    # Step 4: Display lexical overlap between the two texts
    common_words = set(freq1) & set(freq2)
    print(f"\nCommon words: {len(common_words)}")
    print(f"Words unique to {file1}: {len(set(freq1) - set(freq2))}")
    print(f"Words unique to {file2}: {len(set(freq2) - set(freq1))}")

if __name__ == "__main__":
    document_similarity('sample1.txt', 'sample2.txt')

"""
THEORY:

→ PROGRAM OBJECTIVE:
This program computes the *textual similarity* between two documents based on their word
usage using the concept of **Cosine Similarity**. The approach treats each document as
a vector of word frequencies and measures the cosine of the angle between these vectors.

→ APPROACH OVERVIEW:
1. **Read and Clean Documents:**
   Each file is read as plain text. All punctuation marks are removed, and words are
   converted to lowercase for uniformity.
   
2. **Tokenization and Frequency Counting:**
   The text is tokenized into words (splitting by whitespace). The `Counter` class is
   then used to count occurrences of each word, forming a dictionary such as:
   {'hello': 3, 'world': 2, 'python': 1}.

3. **Vector Representation:**
   Each document is represented as a vector of word counts in a shared vocabulary.
   For example:
       Doc1: {"hello": 2, "world": 1}
       Doc2: {"hello": 1, "python": 1}
   The union of all words = {"hello", "world", "python"}.
   Hence, vectors become:
       A = [2, 1, 0]
       B = [1, 0, 1]

4. **Cosine Similarity Computation:**
   Cosine similarity measures how similar two vectors are by comparing their orientation:
       cos(θ) = (A·B) / (||A|| * ||B||)
   where:
       - A·B is the dot product (sum of element-wise products)
       - ||A|| is the magnitude (sqrt of sum of squares)
   If θ = 0°, documents are identical → cos(θ)=1.
   If θ = 90°, documents are completely dissimilar → cos(θ)=0.

5. **Angle Interpretation:**
   The smaller the angle between two vectors, the more similar the documents are.
   Angle is computed using `math.acos(similarity)` for interpretability.

6. **Common & Unique Words:**
   The program also displays:
     - Count of words common to both documents
     - Count of words unique to each document
   This helps understand vocabulary overlap qualitatively.

→ HOW TO RUN:
1. Save the program as `text_similarity.py`.
2. Create two text files, e.g. `sample1.txt` and `sample2.txt` in the same directory.
3. Run the program in terminal:
       python text_similarity.py
4. The script prints:
     - Total and unique words per file
     - Cosine similarity value
     - Angle between documents
     - Number of common and unique words.

→ KEY CONCEPTS:
• **Cosine Similarity** – measures orientation (not magnitude), ideal for text data.
• **Text Normalization** – ensures consistency by lowercasing and removing punctuation.
• **Vector Space Model** – represents text mathematically for comparison.
• **Counter & Dictionary Operations** – used for efficient frequency computation.
• **Angle Interpretation** – useful for comparing degrees of similarity visually.

This method is widely used in Natural Language Processing (NLP) for document clustering,
plagiarism detection, and information retrieval tasks.
"""
