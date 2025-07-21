#!/usr/bin/env python3
"""Check for broken links in markdown files."""

import os
import re
import sys
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

def find_links(content):
    """Find all links in markdown content."""
    # Match both [text](url) and bare <url> formats
    link_patterns = [
        r'\[([^\]]+)\]\(([^)]+)\)',  # [text](url)
        r'<(https?://[^>]+)>',       # <url>
    ]
    
    links = []
    for pattern in link_patterns:
        links.extend(re.findall(pattern, content))
    
    return [link[1] if len(link) > 1 else link[0] for link in links]

def is_valid_url(url):
    """Check if a URL is valid and accessible."""
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        return response.status_code < 400
    except:
        return False

def check_file(file_path, base_url=""):
    """Check all links in a markdown file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    links = find_links(content)
    broken_links = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        for link in links:
            if link.startswith(('http://', 'https://')):
                if not executor.submit(is_valid_url, link).result():
                    broken_links.append(link)
            elif not link.startswith('#'):  # Ignore internal page anchors
                # Check if local file exists
                local_path = os.path.join(os.path.dirname(file_path), link)
                if not os.path.exists(local_path):
                    broken_links.append(link)
    
    return broken_links

def main():
    """Main function to check all markdown files."""
    docs_dir = 'docs'
    broken_links_found = False
    
    for root, _, files in os.walk(docs_dir):
        for file in files:
            if file.endswith('.md'):
                file_path = os.path.join(root, file)
                broken_links = check_file(file_path)
                
                if broken_links:
                    broken_links_found = True
                    print(f"\nBroken links in {file_path}:")
                    for link in broken_links:
                        print(f"  - {link}")
    
    if broken_links_found:
        sys.exit(1)
    else:
        print("No broken links found!")
        sys.exit(0)

if __name__ == '__main__':
    main()
