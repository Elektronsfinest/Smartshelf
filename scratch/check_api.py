import requests

API_URL = "http://localhost:8000" # Assuming default

def check_api():
    # We need a token for adminme@gmail.com
    # But I don't know the password... seed_admin says "imadmin"
    try:
        login_res = requests.post(f"{API_URL}/token", data={"username": "adminme@gmail.com", "password": "imadmin"})
        if not login_res.ok:
            print(f"Login failed: {login_res.status_code} {login_res.text}")
            return
        
        token = login_res.json()["access_token"]
        
        users_res = requests.get(f"{API_URL}/admin/users/", headers={"Authorization": f"Bearer {token}"})
        if not users_res.ok:
            print(f"Fetch users failed: {users_res.status_code} {users_res.text}")
            return
        
        users = users_res.json()
        print(f"Fetched {len(users)} users from API")
        for u in users:
            print(u)
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # This might fail if the server isn't running, but I can't start it easily without knowing how the user runs it.
    # Actually, I'll just check the code more carefully.
    pass
