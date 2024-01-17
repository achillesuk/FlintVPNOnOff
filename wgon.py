import requests
import hashlib
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt

RED = '\033[91m'
GREEN = '\033[92m'
ENDC = '\033[0m'  # Reset color

url = 'http://192.168.8.1/rpc'
username = 'root'
password = 'IAmSkag5545!19811983!'

try:
    # Step1: Get encryption parameters by challenge method
    challenge_data = {
        'jsonrpc': '2.0',
        'method': 'challenge',
        'params': {
            'username': username
        },
        'id': 0
    }


    response = requests.post(url, json=challenge_data)
    response.raise_for_status()
    result = response.json()['result']

    alg = result['alg']
    salt = result['salt']
    nonce = result['nonce']

    # Step2: Generate cipher text using openssl algorithm
    if alg == 1:  # MD5
        cipher_password = md5_crypt.using(salt=salt).hash(password)
    elif alg == 5:  # SHA-256
        cipher_password = sha256_crypt.using(salt=salt, rounds=5000).hash(password)
    elif alg == 6:  # SHA-512
        cipher_password = sha512_crypt.using(salt=salt, rounds=5000).hash(password)
    else:
        raise ValueError('Unsupported algorithm')

    # Step3: Generate hash values for login
    data = f"{username}:{cipher_password}:{nonce}"
    hash = hashlib.md5(data.encode()).hexdigest()

    # Step4: Get sid by login
    login_data = {
        'jsonrpc': '2.0',
        'method': 'login',
        'params': {
            'username': username,
            'hash': hash
        },
        'id': 0
    }

    response = requests.post(url, json=login_data)
    response.raise_for_status()
    result = response.json()['result']

    sid = result['sid']
    
  
    # Step5: Calling other APIs with sid
    system_status_data = {
    "jsonrpc": "2.0",
    "method": "call",
    "params": [
        result['sid'],
        "wg-client",
         "get_status",
        {}
    ],
    "id": 1
}   
    response_data = response.json()
    response = requests.post(url, json=system_status_data)
    response.raise_for_status()
    
    status = response.json()['result']['status']
       
    if status == 0:
        print("VPN has been turned ON")
        system_status_data = {
        "jsonrpc": "2.0",
        "method": "call",
        "params": [
            result['sid'],
            "wg-client",
            "start",
            {
                "group_id": 1076,
                "peer_id": 8353
            }
        ],
        "id": 1
    }
    elif status == 1:
        print("VPN has been turned OFF")
        system_status_data = {
        "jsonrpc": "2.0",
        "method": "call",
        "params": [
            result['sid'],
            "wg-client",
            "stop",
            {}
        ],
        "id": 1
    }
  

    response = requests.post(url, json=system_status_data)
    response.raise_for_status()
    nodes = list(response_data.keys())

except requests.exceptions.RequestException as e:
    print("Request Exception:", e)
except (KeyError, ValueError) as e:
    print("Parameter Exception:", e)
except Exception as e:
    print("An error has occurred:", e)
    