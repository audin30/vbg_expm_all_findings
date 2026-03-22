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

# 1. Introspect VulnerableAsset (find the actual type name)
v_finding_asset_query = """
query {
  __type(name: "VulnerabilityFinding") {
    fields {
      name
      type {
        name
        kind
        ofType {
          name
          kind
        }
      }
    }
  }
}
"""
v_finding = query_wiz(token, v_finding_asset_query)
asset_field = next(f for f in v_finding['data']['__type']['fields'] if f['name'] == 'vulnerableAsset')
asset_type_name = asset_field['type']['name'] or asset_field['type']['ofType']['name']
print(f"VulnerableAsset field type name: {asset_type_name}")

# 2. Introspect that asset type
asset_type_query = f"""
query {{
  __type(name: "{asset_type_name}") {{
    fields {{
      name
    }}
  }}
}}
"""
asset_type = query_wiz(token, asset_type_query)
print(f"\n--- {asset_type_name} Fields ---")
for field in asset_type['data']['__type']['fields']:
    print(f"- {field['name']}")

# 3. Check for CVE related fields in VulnerabilityFinding
print("\n--- CVE related fields in VulnerabilityFinding ---")
for field in v_finding['data']['__type']['fields']:
    if "cve" in field['name'].lower() or "score" in field['name'].lower():
        print(f"- {field['name']}")
