import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import time
from typing import Set, Deque, Optional
import logging
from pathlib import Path

class WebCrawler:
    def __init__(self, start_url: str, max_pages: int = 30, 
                 same_domain: bool = True, delay: float = 1.0):
        """Initialize the web crawler with configuration."""
        self.start_url = start_url
        self.max_pages = max_pages
        self.same_domain = same_domain
        self.delay = delay

        # Frontier implemented as a FIFO queue (BFS). Seed it with start_url.
        self.to_crawl: Deque[str] = deque([start_url])

        # Visited set to avoid revisiting same URL (basic duplicate detection).
        self.visited: Set[str] = set()

        # Extract starting domain to optionally restrict crawling to same domain.
        self.start_domain = urlparse(start_url).netloc

        # Setup logging to both file and console for traceability.
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging to file and console (info + error)."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('crawler.log'),  # persistent log
                logging.StreamHandler()             # console output
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _fetch_page(self, url: str) -> Optional[str]:
        """Fetch page content with basic error handling and timeout.
        
        Returns page HTML text on success, None on failure.
        """
        try:
            # Simple GET request; a production crawler should set a polite User-Agent header.
            response = requests.get(url, timeout=5)
            response.raise_for_status()  # raise for HTTP errors (4xx, 5xx)
            return response.text
        except requests.exceptions.RequestException as e:
            # Log failures (network issues, timeouts, HTTP errors)
            self.logger.error(f"Failed to fetch {url}: {e}")
            return None

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        """Extract, normalize and filter links from HTML content.

        - Uses urljoin to resolve relative URLs against base_url.
        - Filters out non-http(s) schemes.
        - Optionally restricts links to the start domain if same_domain=True.
        """
        links = set()
        soup = BeautifulSoup(html, "html.parser")  # parse HTML

        # Iterate over anchor tags with href attributes.
        for link_tag in soup.find_all("a", href=True):
            # Normalize and resolve relative URLs to absolute URLs
            url = urljoin(base_url, link_tag["href"])

            # Filter invalid or non-web URLs (mailto:, javascript:, tel:, etc.)
            if not url.startswith(("http://", "https://")):
                continue

            # Optionally restrict crawling to same domain to avoid wide web crawling
            if self.same_domain and urlparse(url).netloc != self.start_domain:
                continue

            # Add normalized URL to set (de-duplicates / avoids repeated queue entries)
            links.add(url)
        return links

    def crawl(self) -> Set[str]:
        """Execute the crawling process (BFS):

        - Pop URLs from the frontier (to_crawl).
        - Fetch page, add to visited, extract links, and append unseen links to frontier.
        - Respect a polite delay between requests.
        - Stop when frontier is empty or visited pages reach max_pages.
        """
        self.logger.info(f"Starting crawl from: {self.start_url}")
        self.logger.info(f"Max pages: {self.max_pages}")

        # Loop until we exhaust frontier or reach max_pages
        while self.to_crawl and len(self.visited) < self.max_pages:
            url = self.to_crawl.popleft()  # FIFO -> breadth-first crawl

            # Skip if already visited (duplicate check)
            if url in self.visited:
                continue

            # Respect politeness: pause between requests to avoid hammering the server
            time.sleep(self.delay)

            # Fetch page content (with error handling inside _fetch_page)
            html = self._fetch_page(url)
            if html:
                # Mark URL as visited only after successful fetch to avoid marking broken URLs
                self.visited.add(url)
                self.logger.info(f"Crawled ({len(self.visited)}): {url}")

                # Extract and normalize links from the page, then enqueue unseen ones
                new_links = self._extract_links(html, url)
                for link in new_links:
                    if link not in self.visited:
                        self.to_crawl.append(link)

        return self.visited

    def save_results(self, filename: str = "crawl_results.txt"):
        """Save crawling results to a text file (simple report)."""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Web Crawler Results\n")
            f.write(f"==================\n")
            f.write(f"Start URL: {self.start_url}\n")
            f.write(f"Pages Crawled: {len(self.visited)}\n\n")
            f.write("Visited Pages:\n")
            for page in sorted(self.visited):
                f.write(f"- {page}\n")


def main():
    # Configuration: change START_URL and MAX_PAGES as needed for experiments.
    START_URL = "https://docs.python.org/3/"
    MAX_PAGES = 30

    # Instantiate crawler with desired behavior:
    # same_domain=True keeps the crawl local to the docs.python.org domain.
    crawler = WebCrawler(
        start_url=START_URL,
        max_pages=MAX_PAGES,
        same_domain=True,
        delay=1.0
    )

    # Run crawl and collect set of visited pages
    visited_pages = crawler.crawl()

    # Persist results and print simple summary to console
    crawler.save_results()

    print(f"\nCrawling completed.")
    print(f"Total unique pages visited: {len(visited_pages)}")
    print(f"Results saved to: crawl_results.txt")
    print(f"Log saved to: crawler.log")


if __name__ == "__main__":
    main()

"""
theory (very detailed)

## what this program implements

a simple, polite, domain-restricted web crawler (a.k.a. spider). it starts from a seed URL,
fetches pages, extracts links, and follows them until it reaches a page limit. it uses BFS
(frontier as a queue), respects a fixed delay between requests, and optionally restricts to
the same domain. results and logs are saved for later inspection.

## core components and why they matter

1. frontier (to_crawl):

   * a queue of URLs to visit. this implementation uses a FIFO queue (collections.deque),
     which performs a breadth-first search (bfs). bfs tends to discover shallower pages
     first (good for site-wide coverage). alternative: stack → depth-first.

2. visited set:

   * prevents duplicate visits. without it the crawler may loop forever on circular links.
   * crucial for correctness and to minimize requests.

3. fetcher (_fetch_page):

   * issues HTTP GET requests. handle:

     * network timeouts
     * HTTP errors (4xx/5xx)
     * transient failures (timeouts, connection resets)
   * production crawlers add:

     * custom User-Agent (identify crawler)
     * request headers (Accept-Language, etc.)
     * retry with exponential backoff for transient errors
     * connection pooling (requests.Session) for efficiency

4. parser and link extractor (_extract_links):

   * uses BeautifulSoup to parse html and extract anchor tags.
   * urljoin resolves relative URLs to absolute (important).
   * normalization steps (not exhaustive here) can include:

     * removing fragments (#fragment)
     * canonicalizing scheme and host (http vs https)
     * percent-decoding/encoding normalization
     * removing or considering query parameters
     * respecting rel="nofollow" or meta robots tags (optional policy)
   * filtering:

     * skip non-http schemes (mailto:, tel:, javascript:)
     * domain restriction when same_domain=True

5. politeness (delay) and robots.txt:

   * politeness: sleep between requests (delay param) to avoid overloading web servers.
   * robots.txt (IMPORTANT): production crawlers MUST check robots.txt for disallow rules
     and obey crawl-delay directives. python's urllib.robotparser can be used to parse robots.txt.
   * this demo uses a fixed delay and a simplified note about robots.txt; real crawlers must parse it.

6. duplicate detection and canonical URLs:

   * canonical URLs or different URLs with same content lead to duplication.
   * strategies:

     * normalize URLs
     * store canonical link relations (rel=canonical)
     * content fingerprinting (hash or shingling) to detect identical content

7. error handling and robustness:

   * log errors and continue
   * avoid marking URL visited on fetch failure (this program marks visited only on success)
   * avoid infinite loops and extremely large resource consumption (max_pages)

## important crawling strategies (and when to use them)

* breadth-first (BFS): good for breadth coverage and small-depth discovery (site maps).
* depth-first (DFS): may dive deep into long paths; useful for focused crawling on specific paths.
* focused crawling: use content heuristics (keywords) to prioritize frontier for relevant pages.
* politeness by host: use per-host queues and delays to avoid hitting one host too hard.
* priority queue: rank frontier by score (e.g., page importance or freshness).

## robots, ethics, and legal considerations

* always respect robots.txt and terms of service.
* identify your crawler with an appropriate User-Agent and contact info if possible.
* rate-limit aggressively on shared or small servers.
* be mindful of copyright and privacy when storing content.
* do not crawl authenticated or private areas unless authorized.

## advanced features for real crawlers (beyond this simple demo)

* robots.txt parsing and obeying Disallow / Crawl-delay.
* politeness per host name (separate queues and timers per host).
* handling cookies, sessions, and JavaScript-rendered pages (headless browsers like Playwright / Selenium).
* incremental crawling: store crawl state (frontier + visited) for continuation.
* distributed crawling: coordinate multiple workers across machines (divide frontier by domain/host).
* sitemaps: use site’s sitemap.xml for efficient discovery.
* content deduplication: shingling, minhash, or comparing hash fingerprints.
* canonicalization: follow rel=canonical to reduce duplicates and handle duplicate content.
* URL canonical forms and normalization (strip session ids, sort query params).
* politeness, throttling, backoff strategies (exponential backoff on repeated 429/503 errors).
* prioritization: apply heuristics (pagerank, inbound links, last-modified) to choose next URLs.
* persistence: store crawl graph, page content, metadata, and timestamps in a DB.

## data structures and storage

* frontier: queue (FIFO), priority queue, or per-host queues.
* visited: set / bloom filter (for memory efficient dedup in large-scale crawls).
* content store: files, databases, or object storage for raw HTML and extracted metadata.
* index: inverted index for search engines; graph database for link analysis.

## politeness and performance tradeoffs

* smaller delay = faster crawl but higher server load.
* per-host delay prevents overwhelming a single host while allowing parallelism across multiple hosts.
* concurrency: use worker pools (asyncio, threading, multiprocessing) to speed up but must still be polite.

## handling dynamic content (javascript)

* many modern sites render links/content via JavaScript. simple HTML parsing then fails.
* solutions:

  * use headless browsers (e.g., Playwright, Selenium) to render JS and extract post-render DOM.
  * use hybrid approaches: static HTML parsing + selective JS rendering for pages needing it.

## link extraction caveats

* relative vs absolute URLs: use urljoin(base, href).
* fragments (#) should be removed when they don't denote different resources.
* trailing slashes, default index pages (index.html), and trailing parameters can create duplicate URLs.

## example improvements (practical suggestions)

* add requests.Session() to reuse TCP connections.
* set headers = {'User-Agent': 'YourCrawler/1.0 ([+email@example.com](mailto:+email@example.com))'}
* respect robots.txt via urllib.robotparser.RobotFileParser
* consider using a small sleep jitter (randomized delay) to avoid synchronized bursts
* log response headers (content-type) and skip non-HTML content (e.g., images, pdfs)
* limit content size by streaming response and stopping after X bytes

## how to run this program

1. install dependencies:
   pip install requests beautifulsoup4

2. run:
   python crawler.py
   (modify START_URL and MAX_PAGES in main() as needed)

3. outputs:

   * crawl_results.txt : list of visited pages
   * crawler.log       : detailed log of crawl progress and errors

## viva-ready brief (concise answers to expected questions)

* why urljoin? → resolves relative links to absolute using base URL, essential for correct crawling.
* why visited set? → prevents duplicate requests and infinite loops on circular links.
* why delay? → politeness: avoid overwhelming servers and respect site resources.
* how to obey robots.txt? → parse robots.txt and skip disallowed paths (urllib.robotparser).
* difference between BFS and DFS? → BFS explores breadth (level-order), DFS explores deep paths.
* how to handle dynamic JS content? → use headless browser rendering or api endpoints where available.

## limitations of this demo

* does not parse/obey robots.txt automatically
* single-threaded and synchronous (slower for large-scale crawls)
* no per-host rate control or politeness beyond fixed delay
* no robust URL normalization or canonical detection
* doesn't persist frontier/visited across runs (no resume support)

## closing notes

this crawler is intentionally simple to illustrate the core crawling loop:
seed → fetch → parse → extract links → enqueue unseen → repeat. extend each step
(with robots, politeness, deduplication, JS handling, storage, distributed coordination)
to build a production-ready crawler.
"""
