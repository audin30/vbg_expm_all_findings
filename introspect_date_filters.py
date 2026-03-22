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

# 1. Introspect IssueFilters for createdAt and statusChangedAt
q = """
query {
  __type(name: "IssueFilters") {
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
res = query_wiz(token, q)
fields = res['data']['__type']['inputFields']
for f_name in ['createdAt', 'statusChangedAt']:
    field = next(f for f in fields if f['name'] == f_name)
    type_name = field['type']['name'] or field['type']['ofType']['name']
    print(f"--- {f_name} type: {type_name} ---")
    
    q_type = f"""
    query {{
      __type(name: "{type_name}") {{
        inputFields {{
          name
        }}
      }}
    }}
    """
    res_type = query_wiz(token, q_type)
    for f in res_type['data']['__type']['inputFields']:
        print(f"- {f['name']}")
