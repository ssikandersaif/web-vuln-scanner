import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

def crawl(url):
    response = requests.get(url, timeout=5)
    soup = BeautifulSoup(response.text, "html.parser")

    urls = set()
    forms = []

    for link in soup.find_all("a", href=True):
        full_url = urljoin(url, link["href"])
        urls.add(full_url)

    for form in soup.find_all("form"):
        form_details = {
            "action": urljoin(url, form.get("action")),
            "method": form.get("method", "get").lower(),
            "inputs": [i.get("name") for i in form.find_all("input") if i.get("name")]
        }
        forms.append(form_details)

    return urls, forms
