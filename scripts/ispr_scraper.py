"""
ISPR (Inter-Services Public Relations) Press Releases Scraper.

Collects public military and defense statements for geopolitical tension scoring.
"""
import logging
from typing import List, Dict, Any
import httpx
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ispr_scraper")


async def scrape_ispr_statements() -> List[Dict[str, Any]]:
    """Scrape recent public defense press releases."""
    url = "https://ispr.gov.pk/press-release.php"
    results = []
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for item in soup.select(".news-box, .press-item, article")[:10]:
                    title = item.get_text(strip=True)
                    if title:
                        results.append({"title": title, "source": "ispr"})
    except Exception as e:
        logger.warning(f"ISPR scraper fetch failed (expected if blocked): {e}")
    return results


if __name__ == "__main__":
    import asyncio
    data = asyncio.run(scrape_ispr_statements())
    print(f"Scraped {len(data)} statements.")
