import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

WIZ_CLIENT_ID = os.getenv("WIZ_CLIENT_ID")
WIZ_CLIENT_SECRET = os.getenv("WIZ_CLIENT_SECRET")
WIZ_API_URL = os.getenv("WIZ_API_URL")

def get_wiz_token():
    payload = {
        "grant_type": "client_credentials",
        "audience": "wiz-api",
        "client_id": WIZ_CLIENT_ID,
        "client_secret": WIZ_CLIENT_SECRET
    }
    response = requests.post("https://auth.app.wiz.io/oauth/token", data=payload)
    return response.json().get("access_token")

def query_wiz(token, query):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(WIZ_API_URL, json={'query': query}, headers=headers)
    return response.json()

token = get_wiz_token()

# Introspect Query for inventory-like fields
q = """
query {
  __type(name: "Query") {
    fields {
      name
      args {
        name
      }
    }
  }
}
"""
res = query_wiz(token, q)
print("--- Search for Inventory Queries ---")
fields = res['data']['__type']['fields']
target_fields = ['cloudResources', 'cloudResourcesV2', 'graphSearch', 'inventory']
for field in fields:
    if any(target in field['name'] for target in target_fields):
        args = [a['name'] for a in field['args']]
        print(f"- {field['name']}({', '.join(args)})")
