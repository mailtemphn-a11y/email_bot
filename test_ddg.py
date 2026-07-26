from ddgs import DDGS
import re

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

def search_emails_ddg(domain):
    emails = set()
    queries = [
        f'site:{domain} "hr@" OR "career@" OR "jobs@"',
        f'site:{domain} "info@" OR "contact@" OR "office@"',
        f'"{domain}" email',
    ]
    
    with DDGS() as ddgs:
        for query in queries:
            try:
                results = list(ddgs.text(query, max_results=10))
                for r in results:
                    text = f"{r.get('title', '')} {r.get('body', '')} {r.get('href', '')}"
                    found = EMAIL_REGEX.findall(text)
                    for email in found:
                        if domain in email.lower():
                            emails.add(email)
            except Exception as e:
                print(f"Ошибка: {e}")
    
    return list(emails)

print("=== omk.ru ===")
print(search_emails_ddg("omk.ru"))

print("\n=== yandex.ru ===")
print(search_emails_ddg("yandex.ru"))