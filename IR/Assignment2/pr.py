from typing import Dict, List
import numpy as np
from collections import defaultdict

def page_rank(graph: Dict[str, List[str]], damping_factor: float = 0.85,
              max_iterations: int = 100, tolerance: float = 1e-6) -> Dict[str, float]:
    """
    Calculate PageRank scores for pages in a web graph.

    Args:
        graph: A dictionary representing the web graph as {page: [list_of_outbound_links]}
        damping_factor: Probability of continuing to follow links (default 0.85)
        max_iterations: Maximum iterations before stopping (default 100)
        tolerance: Minimum change threshold for convergence (default 1e-6)

    Returns:
        Dictionary mapping each page to its final PageRank score.
    """

    num_pages = len(graph)

    # Initialize equal rank for all pages initially: (1 / N)
    ranks = {page: 1.0 / num_pages for page in graph}

    for iteration in range(max_iterations):
        new_ranks = {}
        total_diff = 0.0

        # Step 1: Initialize each page's base rank component — random jump probability.
        # This handles the case where the user jumps to any random page.
        for page in graph:
            new_ranks[page] = (1 - damping_factor) / num_pages

        # Step 2: Distribute PageRank through outbound links.
        for page, links in graph.items():
            if links:
                # Share of current page's rank divided among its outbound links.
                share = ranks[page] / len(links)
                for linked_page in links:
                    new_ranks[linked_page] += damping_factor * share
            else:
                # Dangling node (no outbound links): distribute its rank evenly among all pages.
                share = ranks[page] / num_pages
                for other_page in graph:
                    new_ranks[other_page] += damping_factor * share

        # Step 3: Compute total difference between new and old ranks to check for convergence.
        total_diff = sum(abs(new_ranks[page] - ranks[page]) for page in graph)

        # Update ranks for next iteration
        ranks = new_ranks.copy()

        # If changes are smaller than tolerance, stop early (convergence reached)
        if total_diff < tolerance:
            print(f"Converged after {iteration + 1} iterations (diff: {total_diff:.8f})")
            break
    else:
        print(f"Maximum iterations ({max_iterations}) reached before full convergence")

    return ranks


def print_rankings(ranks: Dict[str, float], graph: Dict[str, List[str]]) -> None:
    """Print PageRank scores with inbound/outbound link statistics."""
    print("\nPageRank Analysis Results")
    print("=" * 50)

    # Sort pages by descending PageRank score
    sorted_ranks = sorted(ranks.items(), key=lambda x: x[1], reverse=True)

    print("\nPage Rankings:")
    print("-" * 20)
    for page, score in sorted_ranks:
        # Calculate inbound and outbound link counts
        inbound = sum(1 for p, links in graph.items() if page in links)
        outbound = len(graph[page])
        print(f"Page {page:2}: {score:.4f} (In: {inbound}, Out: {outbound})")

    # Print overall network statistics
    print("\nNetwork Statistics:")
    print("-" * 20)
    total_links = sum(len(links) for links in graph.values())
    print(f"Total Pages: {len(graph)}")
    print(f"Total Links: {total_links}")
    print(f"Average Rank: {sum(ranks.values()) / len(ranks):.4f}")


def main():
    # Example directed web graph (Adjacency List)
    example_graph = {
        'A': ['B', 'C'],
        'B': ['C'],
        'C': ['A'],
        'D': ['C'],
        'E': ['A', 'D']
    }

    # Compute PageRank using the defined function
    ranks = page_rank(example_graph)

    # Print the computed PageRank values
    print_rankings(ranks, example_graph)


if __name__ == "__main__":
    main()


"""
THEORY:

→ PROGRAM OBJECTIVE:
This program implements the **PageRank Algorithm**, which measures the importance
of web pages based on the structure of links among them. It was originally developed
by Larry Page and Sergey Brin for the Google search engine to rank web pages.

→ APPROACH OVERVIEW:
1. **Input Representation (Web Graph):**
   The web is represented as a *directed graph* where each node (page) contains
   outbound links to other pages.
   Example:
       A → [B, C]
       B → [C]
       C → [A]
       D → [C]
       E → [A, D]

2. **Initialization:**
   - Every page starts with an equal rank value (1 / N), where N = total pages.
   - The rank values are updated iteratively until convergence.

3. **PageRank Formula:**
   The rank of a page P is given by:
       PR(P) = (1 - d)/N  +  d * Σ [ PR(Q) / L(Q) ]
   where:
       - d = damping factor (usually 0.85)
       - N = total number of pages
       - Q = each page linking to P
       - L(Q) = number of outbound links from page Q
       - (1 - d)/N ensures that the user can randomly jump to any page
         instead of following a link (to avoid getting stuck in link loops).

4. **Dangling Nodes:**
   Pages with no outbound links are called *dangling nodes*.
   Their rank is evenly distributed among all pages in each iteration.

5. **Iteration & Convergence:**
   - In each iteration, ranks are recalculated based on current link contributions.
   - The process continues until the total change between iterations (|new - old|)
     becomes smaller than a threshold (`tolerance`), indicating convergence.

6. **Damping Factor Explanation:**
   The damping factor simulates user behavior:
   - With probability `d`, the user follows a link from the current page.
   - With probability `1 - d`, the user jumps to a random page.

7. **Convergence Criteria:**
   After every iteration, the program computes:
       total_diff = Σ |new_rank - old_rank|
   When this value is less than a small number (e.g., 1e-6), the algorithm stops.

8. **Interpreting Output:**
   - Pages with higher PageRank scores are more "important" or central in the network.
   - The sum of all PageRank scores across pages ≈ 1 (after normalization).

9. **How to Run:**
   - Save this file as `pagerank.py`.
   - Modify or extend the `example_graph` dictionary to simulate any web structure.
   - Run:
         python pagerank.py
   - The program displays:
       → PageRank of each node
       → Number of inbound/outbound links
       → Convergence iteration
       → Network-level statistics

10. **Applications of PageRank:**
    • Web Search Engine ranking  
    • Social Network influence analysis  
    • Citation network analysis  
    • Recommendation systems  

→ SUMMARY:
PageRank models the “random surfer” concept — a probabilistic approach that reflects
how users navigate the web. By iteratively propagating importance through hyperlinks
and accounting for random jumps, the algorithm efficiently ranks pages by relevance
and connectivity.
"""
"""
============================ THEORY: PAGE RANK ALGORITHM ============================

👉 Approach and How It Works:
The PageRank algorithm was originally developed by Google founders (Larry Page and Sergey Brin) 
to rank web pages based on their importance. The basic idea is that a page is important if 
many other important pages link to it.

In this program, we represent the web as a directed graph where:
- Each node represents a web page.
- Each edge (A → B) means page A links to page B.

Initially, each page is assigned an equal rank (1/N). Then, in each iteration, 
each page distributes its rank evenly among the pages it links to. The process continues 
until the ranks stabilize (difference < tolerance), i.e., convergence.

The damping factor (usually 0.85) represents the probability that a user will 
continue clicking on links instead of jumping randomly to another page. 
This prevents “rank sinks” where users get stuck in closed loops.

----------------------------------
👉 Mathematical Formula:
For each page i:
    PR(i) = (1 - d)/N + d * Σ [ PR(j) / L(j) ]  
Where:
- PR(i): PageRank of page i
- d: Damping factor (typically 0.85)
- N: Total number of pages
- L(j): Number of outbound links from page j
- The summation is over all pages j that link to page i

----------------------------------
👉 Explanation of Key Concepts:
1. **Damping Factor (d)**:
   - Represents probability of continuing link traversal.
   - Remaining (1-d) is probability of random jump to any page.
   - Helps handle isolated pages and ensures the matrix is stochastic.

2. **Dangling Nodes**:
   - Pages with no outbound links.
   - Their rank is evenly distributed among all pages in the network.

3. **Convergence**:
   - The iterative algorithm repeats until PageRank values stabilize.
   - The “tolerance” value defines how small the difference must be to stop.

4. **Normalization**:
   - The sum of all PageRank scores ≈ 1 (ensures probability interpretation).

5. **Importance**:
   - Higher PageRank = more important page.
   - Reflects both quantity and quality of incoming links.

----------------------------------
👉 Example Interpretation:
If page A is linked by B and C, and both B and C have high ranks,
then A’s rank will increase too. The algorithm captures the idea that 
“important pages are linked by other important pages.”

----------------------------------
👉 Applications:
- Google search ranking
- Citation analysis (scientific papers)
- Social network analysis
- Recommendation systems
- Web crawling prioritization

----------------------------------
👉 Steps to Run the Program:
1. Define your graph as a dictionary: { 'A': ['B', 'C'], ... }
2. Run the script.
3. The output displays:
   - PageRank of each page (sorted)
   - Inbound and outbound link counts
   - Network statistics

----------------------------------
👉 Advantages:
- Simple and iterative to implement.
- Provides global importance measure.
- Works well on large-scale web graphs.

----------------------------------
👉 Limitations:
- Needs multiple iterations to converge.
- Sensitive to dangling nodes and cycles.
- Static nature (needs recalculation if graph changes).

====================================================================================
"""