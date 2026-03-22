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

# 2. Introspect Query fields again, look for anything with issue
q2 = """
query {
  __type(name: "Query") {
    fields {
      name
    }
  }
}
"""
res2 = query_wiz(token, q2)
query_fields = [f['name'] for f in res2['data']['__type']['fields'] if 'issue' in f['name'].lower()]
print("\n--- Query Fields with 'Issue' ---")
print(", ".join(query_fields))

# 3. If issuesV2 is in Query, find the input type
if 'issuesV2' in query_fields:
    q3 = """
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
    res3 = query_wiz(token, q3)
    v2_field = next(f for f in res3['data']['__type']['fields'] if f['name'] == 'issuesV2')
    v2_filter_arg = next(a for a in v2_field['args'] if a['name'] == 'filterBy')
    v2_filter_type_name = v2_filter_arg['type']['name'] or v2_filter_arg['type']['ofType']['name']
    
    q4 = f"""
    query {{
      __type(name: "{v2_filter_type_name}") {{
        inputFields {{
          name
          type {{
            name
            kind
            ofType {{ name kind }}
          }}
        }}
      }}
    }}
    """
    res4 = query_wiz(token, q4)
    print(f"\n--- {v2_filter_type_name} Fields ---")
    for f in res4['data']['__type']['inputFields']:
        print(f"- {f['name']}")
