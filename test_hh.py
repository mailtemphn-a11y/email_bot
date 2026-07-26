import requests

HH_HEADERS = {
    "User-Agent": "EmailHunterBot/1.0 (contact: mailtemphn@gmail.com)"
}

def search_hh(query, area="1"):
    url = "https://api.hh.ru/vacancies"
    params = {"text": query, "area": area, "per_page": 5}
    try:
        r = requests.get(url, headers=HH_HEADERS, params=params, timeout=15)
        print(f"Status: {r.status_code}")
        data = r.json()
        print(f"Found total: {data.get('found', 0)}")
        items = data.get("items", [])
        print(f"Returned: {len(items)}")
        for item in items[:3]:
            emp = item.get("employer", {})
            print(f"  - {item.get('name')} | {emp.get('name')} | {emp.get('id')}")
        return items
    except Exception as e:
        print(f"Error: {e}")
        return []

print("=== Тест: коммерческий директор Москва ===")
search_hh("коммерческий директор", "1")

print("\n=== Тест: менеджер по продажам ===")
search_hh("менеджер по продажам", "1")