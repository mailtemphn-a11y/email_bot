import asyncio
import os
import re
import sys
from urllib.parse import urljoin, urlparse

import requests
import whois
from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart
from aiogram.types import Message
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

# Регулярка для поиска email
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Заголовки, чтобы сайты не блокировали запросы
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}


def extract_emails(text: str) -> list:
    """Извлекает email из текста."""
    return list(set(EMAIL_REGEX.findall(text)))


def fetch_url(url: str) -> str | None:
    """Загружает страницу по URL."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        return response.text
    except Exception:
        return None


def find_contact_links(base_url: str, html: str) -> list:
    """Ищет ссылки на страницы контактов."""
    soup = BeautifulSoup(html, "html.parser")
    links = []
    keywords = ["contact", "contacts", "kontakt", "about", "kontakty"]
    
    for a in soup.find_all("a", href=True):
        href = a["href"].lower()
        text = a.get_text(strip=True).lower()
        if any(k in href or k in text for k in keywords):
            full_url = urljoin(base_url, a["href"])
            links.append(full_url)
    
    return list(set(links))


def get_whois_emails(domain: str) -> list:
    """Ищет email через WHOIS домена."""
    try:
        w = whois.whois(domain)
        emails = w.email
        if isinstance(emails, str):
            return [emails]
        elif isinstance(emails, list):
            return emails
    except Exception:
        pass
    return []


async def search_emails(url: str) -> dict:
    """Основная функция поиска email."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    result = {
        "site_emails": [],
        "contact_emails": [],
        "whois_emails": []
    }
    
    # 1. Ищем на главной странице
    html = fetch_url(url)
    if html:
        result["site_emails"] = extract_emails(html)
        
        # 2. Ищем на страницах контактов
        contact_links = find_contact_links(url, html)
        for link in contact_links[:3]:
            contact_html = fetch_url(link)
            if contact_html:
                emails = extract_emails(contact_html)
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
            "и я найду доступные email для связи."
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
        
        all_emails = list(set(
            result["site_emails"] + 
            result["contact_emails"] + 
            result["whois_emails"]
        ))
        
        # Фильтруем мусор
        filtered = [e for e in all_emails if not e.endswith((
            "example.com", "test.com", "domain.com", "email.com"
        ))]
        
        if not filtered:
            await message.answer(
                "😕 Email не найден.\n\n"
                "Попробуй указать полный URL (https://site.ru)"
            )
            return
        
        text = f"📧 Найдено {len(filtered)} email(ов) для {url}:\n\n"
        for email in filtered:
            text += f"• {email}\n"
        
        text += "\n✅ Теперь можешь отправить резюме напрямую!"
        await message.answer(text)

    print("Бот запущен...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())