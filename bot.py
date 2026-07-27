import asyncio
import os
import re
import sqlite3
import sys
import time
from urllib.parse import urlparse

import requests
import whois
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, CommandStart
from aiogram.types import Message
from ddgs import DDGS
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

DB_PATH = "companies.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS shown_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            shown_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, domain)
        )
    ''')
    conn.commit()
    conn.close()

def is_domain_shown(user_id: int, domain: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM shown_domains WHERE user_id = ? AND domain = ?", (user_id, domain))
    result = c.fetchone() is not None
    conn.close()
    return result

def mark_domain_shown(user_id: int, domain: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO shown_domains (user_id, domain) VALUES (?, ?)", (user_id, domain))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()

init_db()

# Улучшенная regex — email должен заканчиваться на буквы, не на картинку
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b")
HREF_REGEX = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
}

# Агрегаторы, соцсети, госорганы, СРО
SKIP_DOMAINS = {
    "hh.ru", "avito.ru", "yandex.ru", "google.com", "youtube.com",
    "facebook.com", "instagram.com", "linkedin.com", "twitter.com",
    "wikipedia.org", "news.ru", "ria.ru", "tass.ru", "lenta.ru",
    "cian.ru", "domclick.ru", "irr.ru", "pulscen.ru", "blizko.ru",
    "zoon.ru", "yell.ru", "2gis.ru", "orgpage.ru", "kontur.ru",
    "banki.ru", "sravni.ru", "otzovik.com", "profi.ru",
    "vseinstrumenti.ru", "wildberries.ru", "ozon.ru",
    "market.yandex.ru", "aliexpress.ru", "sberbank.ru", "tinkoff.ru",
    "vtb.ru", "gazprombank.ru", "alfabank.ru", "raiffeisen.ru",
    "jsprav.ru", "spravker.ru", "spravochnik.ru", "org.ru",
    "stroikompanies.ru", "kronotech.ru", "stroykontrol.info",
    "vse-stroyka.ru", "vse-otzivi.ru", "top100.rambler.ru",
    "rating.ru", "rate.ru", "irecommend.ru", "maps.yandex.ru",
    "zastroev.ru", "novostroycity.ru", "novomoscow.ru",
    "stroimaterialy.ru", "stroypark.ru", "stroyka.ru",
    "vse-zastroyshiki.ru", "novostroy-m.ru", "kvartira.ru",
    "nedvizhimost.ru", "realty.ru", "move.ru", "mirkvartir.ru",
    "domofond.ru", "yandex.realty", "etagi.com",
    "m2.ru", "gdeetotdom.ru", "novostroy.su", "incom.ru",
    "bn.ru", "snimi.ru", "rentflot.ru", "kvartus.ru",
    # Соцсети
    "vk.com", "m.vk.com", "t.me", "telegram.org", "facebook.com",
    "instagram.com", "twitter.com", "x.com", "linkedin.com",
    # Госорганы
    "mos.ru", "gov.ru", "garant.ru", "consultant.ru",
    # СРО
    "sro", "npmaap.ru", "sro-apoek.ru", "sroaap.ru", "sroaas.ru",
    "sroo.ru", "sro-soyuz.ru", "np-sro.ru", "sro-rf.ru",
}

# Слова в title — агрегаторы, СРО, госорганы
SKIP_TITLE_WORDS = [
    "топ-", "топ ", "рейтинг", "адреса", "телефоны", "отзывы",
    "справочник", "каталог", "портал", "обзор", "сравнение",
    "где найти", "как выбрать", "лучшие", "подборка",
    "список", "застройщики", "организации", "компании",
    "строительные", "застройщиков", "новостройки",
    "квартиры", "недвижимость", "продажа",
    "сайты", "все ", "полный список", "перечень",
    "карта", "фото", "цены", "подмосковья",
    "СРО", "саморегулируемая", "саморегулируемое", "сообщество",
    "префектура", "административный округ", "округа",
    "правительство", "министерство", "государственн", "муниципал",
    "главная", "вконтакте", "vk", "facebook", "instagram",
]

# Технические email-паттерны
JUNK_EMAIL_PATTERNS = [
    r"^[a-f0-9]{20,}@",
    r"^u002[fF]@",
    r"sentry",
    r"gravatar",
    r"amazonaws",
    r"cloudfront",
    r"heroku",
    r"firebase",
    r"^[0-9a-f]{8,}@",
    r"logo@",
    r"image@",
    r"banner@",
    r"icon@",
    r"avatar@",
]

# Мусорные email
JUNK_EMAILS = {
    "example@example.ru", "example@example.com", "test@test.com",
    "admin@admin.ru", "user@user.ru", "info@info.ru",
}


def extract_emails(text: str) -> list:
    if not text:
        return []
    emails = EMAIL_REGEX.findall(text)
    cleaned = []
    for e in emails:
        e = e.strip().lower()
        # Убираем точки в начале
        while e.startswith("."):
            e = e[1:]
        # Проверяем что это реальный email
        if "@" not in e:
            continue
        parts = e.split("@")
        if len(parts) != 2:
            continue
        domain_part = parts[1]
        # Не должен заканчиваться на картинку
        if domain_part.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")):
            continue
        # Не должен содержать слеши
        if "/" in e:
            continue
        cleaned.append(e)
    return list(set(cleaned))


def fetch_url(url: str, retries: int = 2) -> str | None:
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
        except requests.exceptions.HTTPError:
            if response.status_code in (403, 429, 503):
                return "BLOCKED"
            return None
        except Exception:
            return None
    return None


def is_junk_email(email: str) -> bool:
    lower = email.lower()
    
    # Точные совпадения
    if lower in JUNK_EMAILS:
        return True
    
    # Паттерны
    for pattern in JUNK_EMAIL_PATTERNS:
        if re.search(pattern, lower):
            return True
    
    junk_domains = ["example.com", "test.com", "domain.com", "email.com", "yourdomain.com", "localhost", "site.com", "company.com"]
    junk_prefixes = ["no-reply", "noreply", "donotreply", "robot", "autoreply", "auto-reply", "bounce", "abuse", "dns-admin", "hostmaster", "postmaster", "webmaster", "root", "administrator", "security", "noc", "suporte", "daemon", "mailer-daemon", "list@", "newsletter@"]
    
    if any(email.endswith("@" + d) or email.endswith("." + d) for d in junk_domains):
        return True
    if any(lower.startswith(p) for p in junk_prefixes):
        return True
    return False


def classify_email(email: str) -> str:
    lower = email.lower()
    hr_patterns = ["hr@", "career@", "careers@", "recruitment@", "recruiting@", "jobs@", "vacancy@", "vacancies@", "talent@", "staffing@", "personnel@", "rabota@", "kadry@", "job@", "apply@", "work@", "join@", "hiring@", "hr.", "career.", "recruit.", "job.", "vacancy.", "work."]
    leadership_patterns = ["ceo@", "director@", "chief@", "president@", "manager@", "head@", "founder@", "owner@", "md@", "dir@", "managing@", "executive@", "lead@", "boss@", "supervisor@", "руководство@", "директор@", "гендиректор@", "prezes@", "direktor@", "leiter@"]
    sales_patterns = ["sales@", "marketing@", "bizdev@", "business@", "commercial@", "commerce@", "trade@", "dealer@", "distrib@", "partner@", "b2b@", "client@", "customers@", "zakaz@", "prodaza@", "zakupki@"]
    general_patterns = ["info@", "office@", "contact@", "contacts@", "support@", "admin@", "help@", "service@", "reception@", "general@", "mail@", "post@", "press@", "media@", "pr@", "secretary@", "secretariat@"]
    if any(p in lower for p in hr_patterns):
        return "HR / Найм"
    if any(p in lower for p in leadership_patterns):
        return "Руководство"
    if any(p in lower for p in sales_patterns):
        return "Продажи / Бизнес"
    if any(p in lower for p in general_patterns):
        return "Общий"
    return "Другой"


def is_aggregator_title(title: str) -> bool:
    lower = title.lower()
    for word in SKIP_TITLE_WORDS:
        if word in lower:
            return True
    return False


def search_emails_ddg(domain: str) -> list:
    emails = set()
    queries = [
        f'site:{domain} "hr@" OR "career@" OR "jobs@"',
        f'site:{domain} "info@" OR "contact@" OR "office@"',
        f'site:{domain} "sales@" OR "marketing@" OR "press@"',
        f'"{domain}" email',
    ]
    try:
        with DDGS() as ddgs:
            for query in queries:
                try:
                    results = list(ddgs.text(query, max_results=10))
                    for r in results:
                        text = f"{r.get('title', '')} {r.get('body', '')} {r.get('href', '')}"
                        found = EMAIL_REGEX.findall(text)
                        for email in found:
                            email_clean = email.lower().strip().lstrip(".")
                            if domain in email_clean:
                                emails.add(email_clean)
                except Exception:
                    continue
    except Exception:
        pass
    return list(emails)


def search_emails_for_domain(domain: str) -> dict:
    result = {"emails": {}, "blocked": False}
    ddg_emails = search_emails_ddg(domain)
    for email in ddg_emails:
        if not is_junk_email(email):
            if email not in result["emails"]:
                result["emails"][email] = {"type": classify_email(email), "sources": []}
            if "DuckDuckGo" not in result["emails"][email]["sources"]:
                result["emails"][email]["sources"].append("DuckDuckGo")
    
    url = f"https://{domain}"
    html = fetch_url(url)
    if html == "BLOCKED":
        result["blocked"] = True
    elif html:
        for email in extract_emails(html):
            if not is_junk_email(email):
                if email not in result["emails"]:
                    result["emails"][email] = {"type": classify_email(email), "sources": []}
                if "Сайт" not in result["emails"][email]["sources"]:
                    result["emails"][email]["sources"].append("Сайт")
    
    try:
        w = whois.whois(domain)
        whois_emails = w.email
        if isinstance(whois_emails, str):
            whois_emails = [whois_emails]
        elif isinstance(whois_emails, list):
            whois_emails = [e for e in whois_emails if e and "@" in str(e)]
        else:
            whois_emails = []
        for email in whois_emails:
            email = email.lower().strip().lstrip(".")
            if not is_junk_email(email):
                if email not in result["emails"]:
                    result["emails"][email] = {"type": classify_email(email), "sources": []}
                if "WHOIS" not in result["emails"][email]["sources"]:
                    result["emails"][email]["sources"].append("WHOIS")
    except Exception:
        pass
    
    return result


def clean_title(title: str) -> str:
    suffixes = [
        " — Яндекс", " | Яндекс", " - Google", " | Google",
        " | ВКонтакте", " — ВКонтакте", " | Facebook",
        " | Instagram", " | Twitter", " | LinkedIn",
        " - YouTube", " | YouTube", " | Telegram",
        " - официальный сайт", " | официальный сайт",
        " – официальный сайт", " — официальный сайт",
    ]
    for suffix in suffixes:
        if suffix in title:
            title = title.split(suffix)[0].strip()
    
    title = title.replace("...", "").replace("…", "").strip()
    title = re.sub(r'\s+', ' ', title)
    
    return title


def find_companies_ddg(query: str, user_id: int, limit: int = 10) -> list:
    companies = []
    seen_domains = set()
    
    search_queries = [
        f'{query} официальный сайт',
        f'{query}',
    ]
    
    try:
        with DDGS() as ddgs:
            for sq in search_queries:
                try:
                    results = list(ddgs.text(sq, max_results=25))
                    for r in results:
                        href = r.get("href", "")
                        title = r.get("title", "").strip()
                        if not href or not title:
                            continue
                        
                        if is_aggregator_title(title):
                            continue
                        
                        parsed = urlparse(href)
                        domain = parsed.netloc.replace("www.", "").lower()
                        
                        if not domain:
                            continue
                        
                        # Пропускаем мусорные домены
                        skip = any(domain.endswith("." + d) or domain == d for d in SKIP_DOMAINS)
                        if skip:
                            continue
                        
                        # Пропускаем госдомены (кроме известных компаний)
                        if any(domain.endswith(g) for g in [".gov.ru", ".gov", ".mil", ".mos.ru", ".spb.ru"]):
                            # Разрешаем mosproject.ru, но не sao.mos.ru
                            if "mosproject" not in domain and "project" not in domain:
                                continue
                        
                        # Пропускаем слишком длинные домены
                        if len(domain) > 40:
                            continue
                        
                        # Пропускаем поддомены агрегаторов
                        bad_words = ["sprav", "rating", "top", "catalog", "portal", "review", "list", "directory", "sro", "np-"]
                        if any(w in domain for w in bad_words):
                            continue
                        
                        if domain in seen_domains:
                            continue
                        
                        if is_domain_shown(user_id, domain):
                            continue
                        
                        seen_domains.add(domain)
                        clean = clean_title(title)
                        
                        if is_aggregator_title(clean):
                            continue
                        
                        companies.append({
                            "name": clean,
                            "domain": domain,
                            "url": href,
                        })
                        
                        if len(companies) >= limit:
                            break
                except Exception:
                    continue
                
                if len(companies) >= limit:
                    break
    except Exception:
        pass
    
    return companies


def format_company_text(idx: int, company: dict) -> str:
    name = company.get("name", "—")
    domain = company.get("domain", "—")
    emails = company.get("emails", {})
    
    lines = [f"{idx}. {name}"]
    lines.append(f"   🌐 {domain}")
    
    if not emails:
        lines.append("   📧 Email не найден")
    else:
        by_type = {}
        for email, data in emails.items():
            t = data.get("type", "Другой")
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(email)
        
        type_order = ["HR / Найм", "Руководство", "Продажи / Бизнес", "Общий", "Другой"]
        for t in type_order:
            if t in by_type:
                for email in by_type[t]:
                    lines.append(f"   📧 {email} ({t})")
    
    lines.append("")
    return "\n".join(lines)


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
            "Команды:\n"
            "• Отправь сайт (например: omk.ru) — найду email\n"
            "• /find <запрос> — найду компании и их email\n"
            "• /reset — сбросить историю\n\n"
            "Примеры:\n"
            "/find строительные компании Москва\n"
            "/find IT аутсорсинг Санкт-Петербург\n"
            "/find производство труб"
        )

    @dp.message(Command("reset"))
    async def cmd_reset(message: Message) -> None:
        user_id = message.from_user.id
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM shown_domains WHERE user_id = ?", (user_id,))
        conn.commit()
        deleted = c.rowcount
        conn.close()
        await message.answer(f"🗑 История сброшена. Удалено {deleted} записей.")

    @dp.message(Command("find"))
    async def cmd_find(message: Message) -> None:
        query = message.text.replace("/find", "").strip()
        if not query:
            await message.answer(
                "Отправь запрос после /find\n\n"
                "Примеры:\n"
                "/find строительные компании Москва\n"
                "/find IT аутсорсинг СПб\n"
                "/find производство металла"
            )
            return
        
        user_id = message.from_user.id
        await message.answer(f"🔍 Ищу компании: «{query}»\nФильтрую агрегаторы...")
        
        companies = find_companies_ddg(query, user_id, limit=10)
        
        if not companies:
            await message.answer("😕 Компании не найдены. Попробуй другой запрос.")
            return
        
        await message.answer(f"📋 Найдено {len(companies)} компаний. Ищу email...")
        
        companies_with_emails = []
        for comp in companies:
            domain = comp["domain"]
            result = search_emails_for_domain(domain)
            comp["emails"] = result["emails"]
            comp["blocked"] = result["blocked"]
            companies_with_emails.append(comp)
            mark_domain_shown(user_id, domain)
            await asyncio.sleep(1)
        
        total_emails = sum(len(c["emails"]) for c in companies_with_emails)
        companies_with_email = sum(1 for c in companies_with_emails if c["emails"])
        
        header = (
            f"✅ Результаты поиска: «{query}»\n\n"
            f"• Компаний: {len(companies_with_emails)}\n"
            f"• С email: {companies_with_email}\n"
            f"• Всего email: {total_emails}\n\n"
        )
        
        messages = []
        current_msg = header
        current_len = len(header)
        
        for i, comp in enumerate(companies_with_emails, 1):
            block = format_company_text(i, comp)
            if current_len + len(block) > 3800:
                messages.append(current_msg)
                current_msg = block
                current_len = len(block)
            else:
                current_msg += block
                current_len += len(block)
        
        if current_msg:
            messages.append(current_msg)
        
        for msg in messages:
            await message.answer(msg)
        
        await message.answer(
            "✅ Готово!\n\n"
            "Повтори /find для новых компаний.\n"
            "/reset — сбросить историю."
        )

    @dp.message(F.text)
    async def handle_text(message: Message) -> None:
        url = message.text.strip()
        
        if "." not in url or " " in url:
            await message.answer(
                "Отправь сайт компании (например: omk.ru)\n"
                "Или используй /find для поиска компаний"
            )
            return
        
        await message.answer(f"🔍 Ищу email на {url}...")
        
        domain = url.replace("https://", "").replace("http://", "").split("/")[0].replace("www.", "")
        result = search_emails_for_domain(domain)
        emails_data = result.get("emails", {})
        
        if not emails_data:
            await message.answer(
                "😕 Email не найден.\n\n"
                "Возможные причины:\n"
                "• Компания не публикует email публично\n"
                "• Сайт защищён от парсинга\n\n"
                "💡 Попробуй зайти на сайт вручную и найти раздел «Контакты»"
            )
            return
        
        by_type = {}
        for email, data in emails_data.items():
            t = data["type"]
            if t not in by_type:
                by_type[t] = []
            by_type[t].append((email, data["sources"]))
        
        text = f"📧 Найдено {len(emails_data)} email(ов) для {url}:\n\n"
        type_order = ["HR / Найм", "Руководство", "Продажи / Бизнес", "Общий", "Другой"]
        
        for t in type_order:
            if t in by_type:
                text += f"{t}:\n"
                for email, sources in by_type[t]:
                    text += f"  • {email}\n"
                    text += f"    Источник: {', '.join(sources)}\n"
                text += "\n"
        
        text += "✅ Готово! Выбирай подходящий email."
        await message.answer(text)

    print("Бот запущен...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())