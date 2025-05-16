import requests
import json
from pprint import pprint

# должно быть таким же, как в app.py
API_URL = "http://localhost:8080"
API_KEY = "your-secret-api-key-here"
USER_ID = "1"


def print_response(response):
    print(f"Статус: {response.status_code}")
    try:
        pprint(response.json())
    except ValueError:
        print("Ответ не в JSON формате:", response.text)


def test_api():
    print("=== ТЕСТИРОВАНИЕ API ===")
    print(f"API URL: {API_URL}")
    print(f"API KEY: {API_KEY}")
    print(f"USER ID: {USER_ID}\n")

    # 1. Тест получения избранного
    print("1. GET /api/favorites - Получение избранных адресов")
    try:
        response = requests.get(
            f"{API_URL}/api/favorites",
            headers={
                "X-API-KEY": API_KEY,
                "X-USER-ID": USER_ID
            },
            timeout=5
        )
        print_response(response)
    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса: {str(e)}")

    # 2. Тест поиска адреса
    print("\n2. GET /api/search - Поиск адреса")
    try:
        response = requests.get(
            f"{API_URL}/api/search",
            headers={"X-API-KEY": API_KEY},
            params={"q": "Москва, Кремль"},
            timeout=5
        )
        print_response(response)
    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса: {str(e)}")

    # 3. Тест добавления в избранное
    print("\n3. POST /api/favorites - Добавление адреса")
    try:
        new_address = {
            "address": "Тестовый адрес из Python",
            "coordinates": "37.617700,55.755800"
        }

        response = requests.post(
            f"{API_URL}/api/favorites",
            headers={
                "X-API-KEY": API_KEY,
                "X-USER-ID": USER_ID,
                "Content-Type": "application/json"
            },
            json=new_address,
            timeout=5
        )
        print_response(response)

    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса: {str(e)}")


if __name__ == "__main__":
    test_api()
