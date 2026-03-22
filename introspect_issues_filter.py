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

# 1. Introspect Query.issues arguments
q1 = """
query {
  __type(name: "Query") {
    fields {
      name
      args {
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
}
"""
res1 = query_wiz(token, q1)
issues_field = next(f for f in res1['data']['__type']['fields'] if f['name'] == 'issues')
print("--- 'issues' Arguments ---")
print(json.dumps(issues_field['args'], indent=2))

# 2. Find IssueFilters (or whatever filter type is used)
filter_arg = next(a for a in issues_field['args'] if a['name'] == 'filterBy')
filter_type_name = filter_arg['type']['name'] or filter_arg['type']['ofType']['name']
print(f"\nFilter type name: {filter_type_name}")

q2 = f"""
query {{
  __type(name: "{filter_type_name}") {{
    inputFields {{
      name
      type {{
        name
        kind
        ofType {{
          name
          kind
        }}
      }}
    }}
  }}
}}
"""
res2 = query_wiz(token, q2)
print(f"\n--- {filter_type_name} Input Fields ---")
print(json.dumps(res2['data']['__type']['inputFields'], indent=2))
