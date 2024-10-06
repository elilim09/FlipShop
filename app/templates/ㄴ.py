import requests

TOKEN_URL = "https://api.dropboxapi.com/oauth2/token"
APP_KEY = "e5myliqdzbz642u"
APP_SECRET = "z76tgoeurbqvddc"
REDIRECT_URI = "YOUR_REDIRECT_URI"

def exchange_code_for_tokens(code):
    data = {
        "code": code,
        "grant_type": "authorization_code",
        "client_id": APP_KEY,
        "client_secret": APP_SECRET,
        "redirect_uri": REDIRECT_URI
    }
    response = requests.post(TOKEN_URL, data=data)
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]
        print(f"Access Token: {access_token}")
        print(f"Refresh Token: {refresh_token}")
    else:
        print(f"Error: {response.status_code}, {response.text}")

# 사용자가 제공한 코드를 여기에 입력합니다.
exchange_code_for_tokens("H9oqifj0j00AAAAAAAAAO7eWa7r0wfUnordddd8Tuo4")