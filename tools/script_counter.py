#!/usr/bin/env python3
import sys
import argparse
import re
import urllib.request
import urllib.error
from collections import OrderedDict

XSS_CONTENT_TYPES = {
    'text/html', 'image/svg+xml', 'text/xml',
    'application/xml', 'application/xhtml+xml'
}

SCRIPT_TAG_REGEX = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

def is_executable_content_type(content_type):
    if not content_type:
        return False
    ct = content_type.lower().split(';')[0].strip()
    return ct in XSS_CONTENT_TYPES

def fetch_url(url):
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content_type = response.getheader('Content-Type', '')
            body = response.read().decode('utf-8', errors='ignore')
            return body, content_type
    except Exception as e:
        print(f"[-] Error fetching {url}: {e}")
        return None, None

def count_script_tags(body):
    if not body:
        return 0, 0
    
    matches = SCRIPT_TAG_REGEX.findall(body)
    total_scripts = len(matches)
    total_words = 0

    for script_content in matches:
        words = len(re.findall(r'\S+', script_content))
        total_words += words

    return total_scripts, total_words

def main():
    parser = argparse.ArgumentParser(description="Script Tag Counter (Unique URLs Only)")
    parser.add_argument('-l', '--list', required=True, help='Input URLs list file')
    parser.add_argument('-o', '--output', default='unique_paths.txt', help='Output file')
    args = parser.parse_args()

    seen_stats = set()  # (scripts, words) tuple
    processed = 0
    unique_urls = []

    with open(args.list, 'r', encoding='utf-8', errors='ignore') as f:
        urls = [line.strip() for line in f if line.strip().startswith(('http://', 'https://'))]

    print(f"[+] Starting analysis of {len(urls)} URLs...\n")

    for url in urls:
        processed += 1
        print(f"[{processed}/{len(urls)}] Checking: {url}")

        body, content_type = fetch_url(url)

        if not body:
            continue

        if not is_executable_content_type(content_type):
            print(f"    Skipped (Content-Type: {content_type})")
            continue

        scripts_count, words_count = count_script_tags(body)
        stats_key = (scripts_count, words_count)

        if stats_key in seen_stats:
            print(f"    Skipped (Duplicate stats: {scripts_count} scripts, {words_count} words)")
            continue

        seen_stats.add(stats_key)
        unique_urls.append(url)

        print(f"    Scripts: {scripts_count} | Words: {words_count} → Saved")

    with open(args.output, 'w', encoding='utf-8') as out:
        out.write("URL\n")
        out.write("--------------------------------------------------------------------------------\n")
        for url in unique_urls:
            out.write(url + "\n")

    print(f"\n🎉 Analysis Completed!")
    print(f"   Total URLs processed : {processed}")
    print(f"   Unique (Scripts, Words) URLs saved : {len(unique_urls)}")
    print(f"   Results saved to: {args.output}")

if __name__ == "__main__":
    main()
