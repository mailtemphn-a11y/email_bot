import asyncio
import os
import re
import sys
import time
from urllib.parse import urljoin, urlparse

import requests
import whois
from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart
from aiogram.types import Message
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Cache-Control": "max-age=0",
}


def extract_emails(text: str) -> list:
    """Извлекает email из текста."""
    if not text:
        return []
    return list(set(EMAIL_REGEX.findall(text)))


def fetch_url(url: str, retries: int = 2) -> str | None:
    """Загружает страницу с повторными попытками."""
    for attempt in range(retries + 1):
        try:
            response = requests.get(url, headers=HEADERS, timeout=20, allow_redirects=True)
            response.raise_for_status()
            return response.text
        except requests.exceptions.Timeout:
            if attempt < retries:
                time.sleep(2)
                continue
            return None
        except requests.exceptions.HTTPError as e:
            if response.status_code == 403:
                return "BLOCKED"
            return None
        except Exception:
            return None
    return None


def find_contact_links(base_url: str, html: str) -> list:
    """Ищет ссылки на страницы контактов."""
    if not html or html == "BLOCKED":
        return []
    
    links = set()
    keywords = [
        "contact", "contacts", "kontakt", "kontakty", "kontakti",
        "about", "o-kompanii", "o-nas", "company",
        "company/contacts", "company/contact", "about/contacts",
        "en/contacts", "ru/contacts", "contacts.html", "contact.html",
        "kontakty.html", "kontakt.html", "about-us", "about_us",
    ]
    
    # Ищем через регулярку (быстрее, чем BeautifulSoup)
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    hrefs = href_pattern.findall(html)
    
    for href in hrefs:
        href_lower = href.lower()
        if any(k in href_lower for k in keywords):
            full_url = urljoin(base_url, href)
            links.add(full_url)
    
    # Также ищем JSON-LD и meta-теги с email
    return list(links)


def get_whois_emails(domain: str) -> list:
    """Ищет email через WHOIS домена."""
    try:
        w = whois.whois(domain)
        emails = w.email
        if isinstance(emails, str):
            return [emails]
        elif isinstance(emails, list):
            return [e for e in emails if e and "@" in str(e)]
    except Exception:
        pass
    return []


def search_email_in_html(html: str) -> list:
    """Ищет email в HTML, meta-тегах, JSON-LD, schema.org."""
    emails = extract_emails(html)
    
    # Ищем обфусцированные email (name [at] domain [dot] com)
    obfuscated = re.findall(r'([a-zA-Z0-9._%+-]+)\s*\[at\]\s*([a-zA-Z0-9.-]+)\s*\[dot\]\s*([a-zA-Z]{2,})', html)
    for match in obfuscated:
        emails.append(f"{match[0]}@{match[1]}.{match[2]}")
    
    # Ищем email с разделителями (name(at)domain(dot)com)
    obfuscated2 = re.findall(r'([a-zA-Z0-9._%+-]+)\(at\)([a-zA-Z0-9.-]+)\(dot\)([a-zA-Z]{2,})', html)
    for match in obfuscated2:
        emails.append(f"{match[0]}@{match[1]}.{match[2]}")
    
    return list(set(emails))


async def search_emails(url: str) -> dict:
    """Основная функция поиска email."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    result = {
        "site_emails": [],
        "contact_emails": [],
        "whois_emails": [],
        "blocked": False,
    }
    
    # 1. Ищем на главной странице
    html = fetch_url(url)
    if html == "BLOCKED":
        result["blocked"] = True
        return result
    
    if html:
        result["site_emails"] = search_email_in_html(html)
        
        # 2. Ищем на страницах контактов
        contact_links = find_contact_links(url, html)
        for link in contact_links[:5]:
            contact_html = fetch_url(link)
            if contact_html and contact_html != "BLOCKED":
                emails = search_email_in_html(contact_html)
                result["contact_emails"].extend(emails)
        
        result["contact_emails"] = list(set(result["contact_emails"]))
    
    # 3. Ищем через WHOIS
    domain = urlparse(url).netloc.replace("www.", "")
    result["whois_emails"] = get_whois_emails(domain)
    
    return result


async def main() -> None:
    if not BOT_TOKEN:
        print("Ошибка: задайте переменную окружения BOT_TOKEN")
        sys.exit(1)

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()

    @dp.message(CommandStart())
    async def cmd_start(message: Message) -> None:
        await message.answer(
            "Привет! Я ищу email-адреса компаний.\n\n"
            "Отправь мне сайт компании (например: yandex.ru), "
            "и я найду доступные email для связи.\n\n"
            "⚠️ Некоторые сайты защищены от парсинга — "
            "в таком случае попробуй найти email вручную на странице «Контакты»."
        )

    @dp.message(F.text)
    async def handle_text(message: Message) -> None:
        url = message.text.strip()
        
        if "." not in url or " " in url:
            await message.answer("Пожалуйста, отправь сайт компании (например: yandex.ru)")
            return
        
        await message.answer(f"🔍 Ищу email на {url}...")
        
        try:
            result = await search_emails(url)
        except Exception as e:
            await message.answer(f"❌ Ошибка при поиске: {e}")
            return
        
        if result.get("blocked"):
            await message.answer(
                "🚫 Сайт блокирует автоматические запросы.\n\n"
                "Это часто у крупных компаний (ОМК, Газпром и т.д.).\n\n"
                "💡 Совет: зайди на сайт вручную, найди раздел "
                "«Контакты» или «О компании» и скопируй email оттуда."
            )
            return
        
        all_emails = list(set(
            result["site_emails"] + 
            result["contact_emails"] + 
            result["whois_emails"]
        ))
        
        # Фильтруем мусор
        filtered = [e for e in all_emails if not e.endswith((
            "example.com", "test.com", "domain.com", "email.com", "yourdomain.com"
        ))]
        
        # Фильтруем no-reply и технические адреса
        priority = []
        low_priority = []
        for email in filtered:
            lower = email.lower()
            if any(x in lower for x in ["no-reply", "noreply", "donotreply", "robot", "autoreply"]):
                continue
            elif any(x in lower for x in ["info@", "contact@", "sales@", "press@", "hr@", "job@", "recruitment@"]):
                priority.append(email)
            else:
                low_priority.append(email)
        
        final_emails = priority + low_priority
        
        if not final_emails:
            await message.answer(
                "😕 Email не найден.\n\n"
                "Возможные причины:\n"
                "• Сайт защищён от парсинга\n"
                "• Email спрятан в JavaScript\n"
                "• Email есть только в PDF/документах\n\n"
                "💡 Попробуй зайти на сайт вручную и найти раздел «Контакты»"
            )
            return
        
        text = f"📧 Найдено {len(final_emails)} email(ов) для {url}:\n\n"
        
        # Группируем по приоритету
        personal = [e for e in final_emails if not any(x in e.lower() for x in ["info@", "contact@", "sales@", "press@", "hr@", "job@"])]
        general = [e for e in final_emails if any(x in e.lower() for x in ["info@", "contact@", "sales@", "press@", "hr@", "job@"])]
        
        if personal:
            text += "👤 Персональные email (лучше для резюме):\n"
            for email in personal:
                text += f"• {email}\n"
            text += "\n"
        
        if general:
            text += "🏢 Общие email:\n"
            for email in general:
                text += f"• {email}\n"
        
        text += "\n✅ Теперь можешь отправить резюме напрямую!"
        await message.answer(text)

    print("Бот запущен...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())