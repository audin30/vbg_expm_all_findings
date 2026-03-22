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

# 1. Introspect VulnerabilityFinding
v_finding_query = """
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
v_finding = query_wiz(token, v_finding_query)
print("--- VulnerabilityFinding Fields ---")
for field in v_finding['data']['__type']['fields']:
    print(f"- {field['name']}")

# 2. Introspect VulnerableAsset
v_asset_query = """
query {
  __type(name: "VulnerableAsset") {
    fields {
      name
    }
  }
}
"""
v_asset = query_wiz(token, v_asset_query)
if v_asset.get('data') and v_asset['data']['__type']:
    print("\n--- VulnerableAsset Fields ---")
    for field in v_asset['data']['__type']['fields']:
        print(f"- {field['name']}")

# 3. Introspect CreateReportInput
report_input_query = """
query {
  __type(name: "CreateReportInput") {
    inputFields {
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
report_input = query_wiz(token, report_input_query)
print("\n--- CreateReportInput Fields ---")
for field in report_input['data']['__type']['inputFields']:
    print(f"- {field['name']}")
