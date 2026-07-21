import asyncio
import os
import sys

from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart
from aiogram.types import Message
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")


async def main() -> None:
    if not BOT_TOKEN:
        print("Ошибка: задайте переменную окружения BOT_TOKEN в файле .env")
        sys.exit(1)

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()

    @dp.message(CommandStart())
    async def cmd_start(message: Message) -> None:
        await message.answer("Привет! Отправь мне сайт компании.")

    @dp.message(F.text)
    async def handle_text(message: Message) -> None:
        await message.answer(f"Получил: {message.text}")

    print("Бот запущен...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
