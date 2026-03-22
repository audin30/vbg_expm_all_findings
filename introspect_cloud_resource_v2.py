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

# Introspect CloudResourceV2 fields
q1 = """
query {
  __type(name: "CloudResourceV2") {
    fields {
      name
    }
  }
}
"""
res1 = query_wiz(token, q1)
print("--- CloudResourceV2 Fields ---")
for f in res1['data']['__type']['fields']:
    print(f"- {f['name']}")

# Introspect CloudResourceV2 filter args
q2 = """
query {
  __type(name: "Query") {
    fields {
      name
      args {
        name
        type {
          name
          kind
          ofType { name kind }
        }
      }
    }
  }
}
"""
res2 = query_wiz(token, q2)
field = next(f for f in res2['data']['__type']['fields'] if f['name'] == 'cloudResourcesV2')
filter_arg = next(a for a in field['args'] if a['name'] == 'filterBy')
filter_type = filter_arg['type']['name'] or filter_arg['type']['ofType']['name']
print(f"\nFilter Type for cloudResourcesV2: {filter_type}")

q3 = f"""
query {{
  __type(name: "{filter_type}") {{
    inputFields {{
      name
    }}
  }}
}}
"""
res3 = query_wiz(token, q3)
print(f"\n--- {filter_type} Fields ---")
for f in res3['data']['__type']['inputFields']:
    print(f"- {f['name']}")
