import re
import math
import tldextract
from urllib.parse import urlparse

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'reddit.com', 'wikipedia.org', 'twitter.com', 'amazon.com',
    'linkedin.com', 'netflix.com', 'microsoft.com', 'github.com',
    'paypal.com', 'apple.com', 'bing.com', 'chatgpt.com'
}

def extract_features(url):
    try:
        p = urlparse(url)
        ext = tldextract.extract(url)
        domain = ext.domain or ""
        sub = ext.subdomain or ""
        full = ext.top_domain_under_public_suffix.lower()

        url_len = len(url)
        specials = len(re.findall(r'[^a-zA-Z0-9]', url))
        entropy = -sum((url.count(c)/url_len) * math.log2(url.count(c)/url_len) for c in set(url)) if url_len else 0

        return [
            url_len,
            len(domain),
            len(p.path),
            url.count('.'),
            url.count('-'),
            url.count('@'),
            url.count('?'),
            url.count('='),
            url.count('/'),
            int('login' in url.lower()),
            int('bank' in url.lower()),
            int('verify' in url.lower()),
            int(bool(re.match(r'(?:\d{1,3}\.){3}\d{1,3}', p.netloc))),
            sum(c.isdigit() for c in url) / url_len if url_len else 0,
            specials / url_len if url_len else 0,
            entropy,
            int(p.scheme.lower() == 'https'),
            len(sub),
            sum(w in url.lower() for w in ['login','bank','verify','secure','account','update']),
            int(any(h in url.lower() for h in ['000webhost','freenom','infinityfree'])),
            int(any(s in url.lower() for s in ['bit.ly','tinyurl.com','goo.gl','ow.ly','is.gd'])),
            int(any(b in sub.lower() for b in ['paypal','citi','facebook','google','amazon'])),
            int(full in TRUSTED_DOMAINS)
        ]
    except Exception as e:
        print(f"[ERROR] Feature extraction failed: {e}")
        return None
