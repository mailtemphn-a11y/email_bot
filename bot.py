import asyncio
import os
import re
import smtplib
import sys
import time
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urljoin, urlparse

import requests
import whois
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, CommandStart
from aiogram.types import Message
from ddgs import DDGS
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")

# Храним путь к резюме (загружается один раз)
RESUME_PATH = "resume.pdf"

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
HREF_REGEX = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
}

CONTACT_KEYWORDS = [
    "contact", "contacts", "kontakt", "kontakty", "kontakti",
    "about", "o-kompanii", "o-nas", "company", "about-us",
    "company/contacts", "company/contact", "about/contacts",
    "en/contacts", "ru/contacts", "contacts.html", "contact.html",
]

VACANCY_KEYWORDS = [
    "vacancies", "vacancy", "career", "careers", "jobs", "job",
    "hr", "human-resources", "recruitment", "recruiting", "talent",
    "join", "join-us", "team", "rabota", "vakansii",
]

OTHER_KEYWORDS = [
    "press", "media", "pr", "news", "investors", "partners",
]


def extract_emails(text: str) -> list:
    if not text:
        return []
    return list(set(EMAIL_REGEX.findall(text)))


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


def find_links_by_keywords(base_url: str, html: str, keywords: list) -> list:
    if not html or html == "BLOCKED":
        return []
    links = set()
    hrefs = HREF_REGEX.findall(html)
    for href in hrefs:
        href_lower = href.lower()
        if any(k in href_lower for k in keywords):
            full_url = urljoin(base_url, href)
            if urlparse(full_url).netloc.replace("www.", "") == urlparse(base_url).netloc.replace("www.", ""):
                links.add(full_url)
    return list(links)


def classify_email(email: str) -> str:
    lower = email.lower()
    hr_patterns = ["hr@", "career@", "careers@", "recruitment@", "recruiting@", "jobs@", "vacancy@", "vacancies@", "talent@", "staffing@", "personnel@", "rabota@", "kadry@", "job@", "apply@", "work@", "join@", "hiring@", "hr.", "career.", "recruit.", "job.", "vacancy.", "work."]
    leadership_patterns = ["ceo@", "director@", "chief@", "president@", "manager@", "head@", "founder@", "owner@", "md@", "dir@", "managing@", "executive@", "lead@", "boss@", "supervisor@", "руководство@", "директор@", "гендиректор@", "prezes@", "direktor@", "leiter@"]
    sales_patterns = ["sales@", "marketing@", "bizdev@", "business@", "commercial@", "commerce@", "trade@", "dealer@", "distrib@", "partner@", "b2b@", "client@", "customers@", "zakaz@", "prodaza@", "zakupki@"]
    general_patterns = ["info@", "office@", "contact@", "contacts@", "support@", "admin@", "help@", "service@", "reception@", "general@", "mail@", "post@", "press@", "media@", "pr@", "secretary@", "secretariat@"]
    if any(p in lower for p in hr_patterns):
        return "👤 HR / Найм"
    if any(p in lower for p in leadership_patterns):
        return "👔 Руководство"
    if any(p in lower for p in sales_patterns):
        return "💼 Продажи / Бизнес"
    if any(p in lower for p in general_patterns):
        return "🏢 Общий"
    return "❓ Другой"


def is_junk_email(email: str) -> bool:
    lower = email.lower()
    junk_domains = ["example.com", "test.com", "domain.com", "email.com", "yourdomain.com", "localhost", "site.com", "company.com"]
    junk_prefixes = ["no-reply", "noreply", "donotreply", "robot", "autoreply", "auto-reply", "bounce", "abuse", "dns-admin", "hostmaster", "postmaster", "webmaster", "root", "administrator", "security", "noc", "suporte", "daemon", "mailer-daemon", "list@", "newsletter@"]
    if any(email.endswith("@" + d) or email.endswith("." + d) for d in junk_domains):
        return True
    if any(lower.startswith(p) for p in junk_prefixes):
        return True
    return False


def search_email_in_html(html: str) -> list:
    emails = extract_emails(html)
    obf1 = re.findall(r'([a-zA-Z0-9._%+-]+)\s*\[at\]\s*([a-zA-Z0-9.-]+)\s*\[dot\]\s*([a-zA-Z]{2,})', html)
    for m in obf1:
        emails.append(f"{m[0]}@{m[1]}.{m[2]}")
    obf2 = re.findall(r'([a-zA-Z0-9._%+-]+)\(at\)([a-zA-Z0-9.-]+)\(dot\)([a-zA-Z]{2,})', html)
    for m in obf2:
        emails.append(f"{m[0]}@{m[1]}.{m[2]}")
    return list(set(emails))


def get_whois_emails(domain: str) -> list:
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
                            if domain in email.lower():
                                emails.add(email)
                except Exception:
                    continue
    except Exception:
        pass
    return list(emails)


async def search_emails(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"emails": {}, "blocked": False, "pages_checked": []}
    domain = urlparse(url).netloc.replace("www.", "")
    
    ddg_emails = search_emails_ddg(domain)
    for email in ddg_emails:
        if not is_junk_email(email):
            if email not in result["emails"]:
                result["emails"][email] = {"type": classify_email(email), "sources": []}
            if "DuckDuckGo поиск" not in result["emails"][email]["sources"]:
                result["emails"][email]["sources"].append("DuckDuckGo поиск")
    
    html = fetch_url(url)
    if html == "BLOCKED":
        result["blocked"] = True
    elif html:
        result["pages_checked"].append("Главная страница")
        for email in search_email_in_html(html):
            if not is_junk_email(email):
                if email not in result["emails"]:
                    result["emails"][email] = {"type": classify_email(email), "sources": []}
                if "Главная страница" not in result["emails"][email]["sources"]:
                    result["emails"][email]["sources"].append("Главная страница")
        
        contact_links = find_links_by_keywords(url, html, CONTACT_KEYWORDS)
        for link in contact_links[:3]:
            contact_html = fetch_url(link)
            if contact_html and contact_html != "BLOCKED":
                for email in search_email_in_html(contact_html):
                    if not is_junk_email(email):
                        if email not in result["emails"]:
                            result["emails"][email] = {"type": classify_email(email), "sources": []}
                        if "Контакты" not in result["emails"][email]["sources"]:
                            result["emails"][email]["sources"].append("Контакты")
        
        vacancy_links = find_links_by_keywords(url, html, VACANCY_KEYWORDS)
        for link in vacancy_links[:3]:
            vacancy_html = fetch_url(link)
            if vacancy_html and vacancy_html != "BLOCKED":
                for email in search_email_in_html(vacancy_html):
                    if not is_junk_email(email):
                        if email not in result["emails"]:
                            result["emails"][email] = {"type": classify_email(email), "sources": []}
                        if "Вакансии / Карьера" not in result["emails"][email]["sources"]:
                            result["emails"][email]["sources"].append("Вакансии / Карьера")
    
    whois_emails = get_whois_emails(domain)
    for email in whois_emails:
        if not is_junk_email(email):
            if email not in result["emails"]:
                result["emails"][email] = {"type": classify_email(email), "sources": []}
            if "WHOIS домена" not in result["emails"][email]["sources"]:
                result["emails"][email]["sources"].append("WHOIS домена")
    
    return result


def send_email(to_email: str, subject: str, body: str, attachment_path: str | None = None) -> str:
    """Отправляет email через SMTP."""
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return "❌ SMTP не настроен. Проверь переменные EMAIL_ADDRESS и EMAIL_PASSWORD."
    
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = to_email
        msg["Subject"] = subject
        
        msg.attach(MIMEText(body, "plain", "utf-8"))
        
        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, "rb") as f:
                part = MIMEApplication(f.read(), Name=os.path.basename(attachment_path))
            part["Content-Disposition"] = f'attachment; filename="{os.path.basename(attachment_path)}"'
            msg.attach(part)
        
        server = smtplib.SMTP_SSL(SMTP_SERVER, 465)
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        server.quit()
        
        return f"✅ Письмо отправлено на {to_email}"
    except smtplib.SMTPAuthenticationError:
        return "❌ Ошибка авторизации SMTP. Проверь EMAIL_ADDRESS и EMAIL_PASSWORD (должен быть App Password, не обычный пароль Gmail)."
    except Exception as e:
        return f"❌ Ошибка отправки: {e}"


async def main() -> None:
    if not BOT_TOKEN:
        print("Ошибка: задайте переменную окружения BOT_TOKEN")
        sys.exit(1)

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()

    @dp.message(CommandStart())
    async def cmd_start(message: Message) -> None:
        await message.answer(
            "Привет! Я помогаю находить контакты компаний и отправлять резюме.\n\n"
            "Команды:\n"
            "• Отправь сайт (например: omk.ru) — найду email\n"
            "• Отправь PDF с резюме — сохраню для рассылки\n"
            "• /send email@company.ru Текст — отправлю резюме\n\n"
            "Пример:\n"
            "/send info@omk.ru Здравствуйте! Предлагаю свою кандидатуру на позицию коммерческого директора."
        )

    @dp.message(F.document)
    async def handle_document(message: Message) -> None:
        """Обрабатывает загрузку PDF резюме."""
        if not message.document:
            await message.answer("Отправь файл PDF.")
            return
        
        doc = message.document
        if not doc.file_name or not doc.file_name.lower().endswith(".pdf"):
            await message.answer("Пожалуйста, отправь файл в формате PDF.")
            return
        
        await message.answer("⏳ Загружаю резюме...")
        
        try:
            file = await bot.get_file(doc.file_id)
            await bot.download_file(file.file_path, RESUME_PATH)
            await message.answer(
                f"✅ Резюме сохранено: {doc.file_name}\n\n"
                f"Теперь можешь отправить команду:\n"
                f"/send email@company.ru Текст письма"
            )
        except Exception as e:
            await message.answer(f"❌ Ошибка загрузки: {e}")

    @dp.message(Command("send"))
    async def cmd_send(message: Message) -> None:
        """Отправляет резюме на указанный email."""
        if not os.path.exists(RESUME_PATH):
            await message.answer(
                "❌ Резюме не загружено.\n\n"
                "Сначала отправь мне PDF с резюме, потом используй /send."
            )
            return
        
        # Формат: /send email@company.ru Текст письма
        args = message.text.replace("/send", "").strip()
        if not args:
            await message.answer(
                "Использование:\n"
                "/send email@company.ru Здравствуйте, хочу предложить свою кандидатуру..."
            )
            return
        
        parts = args.split(" ", 1)
        if len(parts) < 1 or "@" not in parts[0]:
            await message.answer(
                "❌ Неверный формат.\n\n"
                "Пример:\n"
                "/send info@omk.ru Здравствуйте! Предлагаю свою кандидатуру."
            )
            return
        
        to_email = parts[0].strip()
        body = parts[1].strip() if len(parts) > 1 else "Добрый день! Предлагаю Вашему вниманию моё резюме."
        
        # Формируем тему
        subject = f"Резюме — {EMAIL_ADDRESS.split('@')[0] if EMAIL_ADDRESS else 'Кандидат'}"
        
        await message.answer(f"⏳ Отправляю резюме на {to_email}...")
        
        result = send_email(to_email, subject, body, RESUME_PATH)
        await message.answer(result)

    @dp.message(F.text)
    async def handle_text(message: Message) -> None:
        url = message.text.strip()
        
        if "." not in url or " " in url:
            await message.answer(
                "Отправь сайт компании (например: omk.ru)\n"
                "Или используй /send для отправки резюме"
            )
            return
        
        await message.answer(f"🔍 Ищу email на {url}...")
        
        try:
            result = await search_emails(url)
        except Exception as e:
            await message.answer(f"❌ Ошибка при поиске: {e}")
            return
        
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
        type_order = ["👤 HR / Найм", "👔 Руководство", "💼 Продажи / Бизнес", "🏢 Общий", "❓ Другой"]
        
        for t in type_order:
            if t in by_type:
                text += f"{t}:\n"
                for email, sources in by_type[t]:
                    text += f"  • {email}\n"
                    text += f"    Источник: {', '.join(sources)}\n"
                text += "\n"
        
        text += "✅ Готово! Чтобы отправить резюме:\n/send email@company.ru Текст письма"
        await message.answer(text)

    print("Бот запущен...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())