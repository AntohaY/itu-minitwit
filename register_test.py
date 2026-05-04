import requests
import time

base_url = "http://localhost:8080"
stamp = int(time.time())

json_user = f"py-json-{stamp}"
no_header_user = f"py-no-header-{stamp}"
follower_user = f"py-follower-{stamp}"

auth = ("simulator", "super_safe!")

def show_response(label, response):
    print(f"\n{label}")
    print(f"Status: {response.status_code}")
    print(response.text)

r1 = requests.post(
    f"{base_url}/register",
    json={
        "username": json_user,
        "email": f"{json_user}@example.com",
        "pwd": "secret",
    },
)
show_response("Register with JSON header", r1)

raw_json = (
    f'{{"username":"{no_header_user}",'
    f'"email":"{no_header_user}@example.com",'
    f'"pwd":"secret"}}'
)

r2 = requests.post(
    f"{base_url}/register",
    data=raw_json,
    headers={}
)
show_response("Register without explicit Content-Type", r2)

r3 = requests.post(
    f"{base_url}/register",
    json={
        "username": follower_user,
        "email": f"{follower_user}@example.com",
        "pwd": "secret",
    },
)
show_response("Create follower user", r3)

r4 = requests.post(
    f"{base_url}/fllws/{follower_user}",
    json={"follow": json_user},
    auth=auth,
)
show_response(f"Follow {json_user} from {follower_user}", r4)
