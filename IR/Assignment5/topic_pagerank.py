# ===========================================
# PROGRAM: Topic-Specific PageRank from XML
# ===========================================

import xml.etree.ElementTree as ET
from collections import defaultdict
import math

XML_FILE = "webpages.xml"

def parse_xml(filename):
    """
    Parse the XML file to extract:
      - `pages`: Dictionary mapping each page id to its title and content
      - `graph`: Dictionary representing outgoing links (adjacency list)
    """
    tree = ET.parse(filename)
    root = tree.getroot()
    pages = {}
    graph = {}

    # Traverse each <page> element in the XML
    for page in root.findall('page'):
        pid = page.get('id')

        # Extract <title> and <content> safely
        title_el = page.find('title')
        content_el = page.find('content')
        title = title_el.text.strip() if title_el is not None and title_el.text else ""
        content = content_el.text.strip() if content_el is not None and content_el.text else ""

        # Store metadata
        pages[pid] = {'title': title, 'content': content}

        # Extract outgoing links under <links><link>...</link></links>
        outs = []
        links_el = page.find('links')
        if links_el is not None:
            for l in links_el.findall('link'):
                if l.text and l.text.strip():
                    outs.append(l.text.strip())

        graph[pid] = outs  # adjacency list representation

    return pages, graph


def build_incoming_links(graph):
    """
    Build the reverse mapping (incoming links).
    Returns:
      - incoming: dict[node] -> list of nodes linking to it
      - nodes: list of all nodes
    """
    nodes = list(graph.keys())
    incoming = {n: [] for n in nodes}

    for src, outs in graph.items():
        for dst in outs:
            if dst in incoming:
                incoming[dst].append(src)
            else:
                # If a destination is missing (dangling to external node),
                # we still add it to ensure all nodes are represented.
                incoming.setdefault(dst, []).append(src)
                graph.setdefault(dst, [])  # Add node with no outgoing links

    return incoming, list(graph.keys())


def build_topic_vector(pages, topic_keywords):
    """
    Create a teleportation (topic) vector v based on topic relevance.
    Pages matching any keyword get higher teleportation probability.
    If no page matches, a uniform vector is used.
    """
    v = {}
    total = 0.0
    kws = [k.lower() for k in topic_keywords]  # normalize keywords

    for pid, meta in pages.items():
        text = (meta.get('title', '') + " " + meta.get('content', '')).lower()
        match = any(k in text for k in kws)
        v[pid] = 1.0 if match else 0.0
        total += v[pid]

    # Normalize to sum = 1
    if total == 0.0:
        n = len(pages)
        return {pid: 1.0 / n for pid in pages}
    else:
        return {pid: v[pid] / total for pid in pages}


def topic_pagerank(graph, pages, topic_vector, damping=0.85, tol=1e-6, max_iter=100):
    """
    Compute Topic-Specific PageRank scores.
    Incorporates the teleportation vector derived from topic keywords.
    """
    nodes = list(graph.keys())
    N = len(nodes)

    # Initialize ranks uniformly
    ranks = {n: 1.0 / N for n in nodes}
    out_degree = {n: len(graph.get(n, [])) for n in nodes}

    for i in range(max_iter):
        new_ranks = {}
        dangling_sum = sum(ranks[n] for n, d in out_degree.items() if d == 0)

        # Initialize with teleportation base (topic vector)
        for p in nodes:
            new_ranks[p] = (1.0 - damping) * topic_vector.get(p, 0.0)

        # Precompute incoming links for faster access
        incoming, _ = build_incoming_links(graph)

        # Add contributions from in-links and dangling nodes
        for p in nodes:
            rank_sum = 0.0
            for q in incoming.get(p, []):
                dq = out_degree.get(q, 0)
                if dq > 0:
                    rank_sum += ranks[q] / dq
            # Add dangling mass redistributed according to topic vector
            new_ranks[p] += damping * (rank_sum + dangling_sum * topic_vector.get(p, 0.0))

        # Check convergence
        diff = sum(abs(new_ranks[n] - ranks[n]) for n in nodes)
        ranks = new_ranks
        if diff < tol:
            break

    # Normalize final ranks
    s = sum(ranks.values())
    if s > 0:
        ranks = {n: ranks[n] / s for n in ranks}

    return ranks


def main():
    print("Parsing XML:", XML_FILE)
    pages, graph = parse_xml(XML_FILE)
    print("Pages found:", len(pages))
    print("Graph nodes:", len(graph))

    # Display quick summary
    for pid, meta in pages.items():
        print(f"  {pid}: {meta['title']} (links -> {graph.get(pid, [])})")

    # User-specified topic keywords
    inp = input("\nEnter topic keywords (comma-separated), e.g. 'machine learning, pagerank':\n> ").strip()
    if inp:
        keywords = [k.strip() for k in inp.split(',') if k.strip()]
    else:
        # Default topic keywords
        keywords = ['machine learning', 'pagerank', 'ranking']

    print("Topic keywords:", keywords)

    # Build teleportation vector
    topic_vec = build_topic_vector(pages, keywords)
    print("\nTeleportation (topic) vector (nonzero entries):")
    for pid, w in topic_vec.items():
        if w > 0:
            print(f"  {pid}: {w:.4f} -> {pages[pid]['title']}")

    # Run topic-specific PageRank
    ranks = topic_pagerank(graph, pages, topic_vec, damping=0.85, tol=1e-8, max_iter=200)

    # Display sorted ranks
    print("\nTopic-specific PageRank (sorted):")
    for pid, r in sorted(ranks.items(), key=lambda x: x[1], reverse=True):
        print(f"  Page {pid}  Rank={r:.6f}  Title='{pages[pid]['title']}'")


if __name__ == "__main__":
    main()


"""
==========================================================
THEORY: XML PARSING, WEB GRAPH & TOPIC-SPECIFIC PAGERANK
==========================================================

1. OVERVIEW
------------
This program performs three main tasks:
   (a) Parses XML data describing web pages and their links.
   (b) Constructs a directed graph representation (web graph).
   (c) Computes **Topic-Specific PageRank** values for each page based on given keywords.

2. XML PARSING
---------------
The XML file contains multiple <page> elements, each representing a webpage.
Each <page> has:
   - An 'id' attribute
   - A <title> and <content> tag
   - A <links> section with multiple <link> entries

Example:
<webpages>
  <page id="A">
    <title>Introduction to AI</title>
    <content>Artificial Intelligence basics...</content>
    <links>
      <link>B</link>
      <link>C</link>
    </links>
  </page>
</webpages>

We extract this structure to form:
   - pages: { 'A': {'title': 'Introduction to AI', 'content': '...'} }
   - graph: { 'A': ['B', 'C'] }

3. WEB GRAPH
-------------
A web graph is a directed graph where:
   - Each node = a webpage
   - Each edge = a hyperlink between pages
This adjacency list (dict of lists) forms the foundation for the PageRank computation.

4. PAGERANK CONCEPT
---------------------
PageRank measures the *importance* of a web page based on the number and quality of its incoming links.
Core Idea:
   - A page has high rank if many important pages link to it.
   - Rank is recursively defined as:
       PR(p) = (1 - d)/N + d * Σ(PR(q)/L(q)) for all q linking to p
   where:
       d = damping factor (typically 0.85)
       L(q) = number of outbound links from page q
       N = total number of pages

The damping factor models the probability that a user follows links rather than jumping randomly.

5. TOPIC-SPECIFIC PAGERANK
----------------------------
While classical PageRank treats all pages equally, **Topic-Specific PageRank** biases the random jumps
toward pages related to a specific topic. 

Instead of teleporting uniformly to all pages, it uses a *teleportation vector v* based on topic keywords.

Computation:
   PR_topic(p) = (1 - d)*v[p] + d * Σ(PR_topic(q)/L(q))

Here, v[p] > 0 for pages relevant to the topic (based on keyword matching in title/content).

Thus, pages that are both *well-linked* and *topically relevant* receive higher ranks.

6. DAMPING FACTOR & CONVERGENCE
--------------------------------
The damping factor (usually 0.85) ensures that:
   - There’s always a chance to jump to another page, preventing rank sinks.
   - The iterative process converges.

We iterate until the difference between successive rank vectors (L1 norm) falls below a tolerance `tol`.

7. DANGLING NODES
------------------
A dangling node is a page with no outgoing links.
Its rank mass is distributed across all pages (or, in topic-specific version, according to v[p]).

8. TELEPORTATION VECTOR (TOPIC VECTOR)
---------------------------------------
- Constructed based on topic keywords.
- Each page that contains any keyword (case-insensitive) in its title/content gets higher teleportation probability.
- If no page matches, fallback to a uniform teleportation vector.

9. NORMALIZATION
-----------------
After convergence, the ranks are normalized so that the total sum equals 1.0.

10. HOW TO RUN
---------------
   - Ensure `webpages.xml` is in the same directory.
   - Run the script.
   - Enter topic keywords when prompted.
   - The program displays top-ranked pages for that topic.

This approach forms the basis of **personalized or topic-sensitive search engines**, 
where results are biased toward user interests or predefined themes.

==========================================================
"""
