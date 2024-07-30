from flask import Flask, request, jsonify
import requests, random
import os

app = Flask(__name__)

global_api_key = None
global_cookies = None
account_creation_in_progress = False

def create_account():
    global global_api_key, global_cookies, account_creation_in_progress

    if account_creation_in_progress:
        print("Account creation is already in progress.")
        return

    account_creation_in_progress = True
    print("Starting account creation...")

    try:
        session = requests.Session()
        url = "https://checkmail.live/login.php"
        y = session.get(url)
        global_cookies = session.cookies.get_dict()

        username = 'k' + ''.join(random.choice("1234567890qwertyuioplkjhfdsazxcvbnm") for _ in range(7))
        password = ''.join(random.choice("1234567890qwertyuioplkjhfdsazxcvbnm") for _ in range(6))
        name = ''.join(random.choice("qwertyuioplkjhfdsazxcvbnm") for _ in range(11))

        data = {
            "fullName": name,
            "userName": username,
            "userPwd": password,
            "signUp": ""
        }
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "ar",
            "Cache-Control": "max-age=0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://checkmail.live",
            "Referer": "https://checkmail.live/login.php",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
        }
        response = session.post(url, data=data, headers=headers, cookies=global_cookies)

        if 'Chỉ có thể đăng ký 1 tài khoản ' in response.text:
            print('Need VPN')
        elif 'Chỉ cần nhập tài khoản, không cần nhập mật khẩu!' in response.text:
            url = "https://checkmail.live/?u=api"
            api_key_get = session.get(url, headers=headers, cookies=global_cookies)
            if 'api_key' in api_key_get.text:
                global_api_key = api_key_get.text.split('"api_key": "')[1].split('",')[0]
                print('api_key:', global_api_key)
                with open("config.txt", "w") as f:
                    f.write(f"{global_api_key}\n")
                    f.write(f"{global_cookies}\n")
            else:
                print('API key not found')
        else:
            print('Error, Try Again')
    except Exception as e:
        print(f"Exception occurred during account creation: {e}")
    finally:
        print("Account creation process completed.")
        account_creation_in_progress = False

def load_configuration():
    global global_api_key, global_cookies

    if os.path.exists("config.txt"):
        with open("config.txt", "r") as f:
            global_api_key = f.readline().strip()
            global_cookies = eval(f.readline().strip())
    else:
        create_account()


load_configuration()

def check_and_create_account():
    global global_api_key, global_cookies

    url = "https://checkmail.live/check/"
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "ar-OM,ar;q=0.9",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": "https://checkmail.live",
        "pragma": "no-cache",
        "referer": "https://checkmail.live/",
        "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
    }
    data = {"api_key": global_api_key, "fastCheck": "true", "emails": ["test@example.com"]}
    
    try:
        req = requests.post(url, headers=headers, json=data, cookies=global_cookies)
        response_json = req.json()
        new_creditt = int(response_json.get("new_credit", 0))

        if new_creditt < 70000:
            print("Low credit, triggering create_account()")
            create_account()
    except (ValueError, KeyError, requests.RequestException) as e:
        print(f"Exception occurred during credit check: {e}")

@app.route('/api/email/<email>', methods=['GET'])
def get_email(email):
    if not global_api_key or not global_cookies:
        return jsonify({'error': 'API key or cookies not initialized'}), 500

    url = "https://checkmail.live/check/"
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "ar-OM,ar;q=0.9",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": "https://checkmail.live",
        "pragma": "no-cache",
        "referer": "https://checkmail.live/",
        "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
    }
    data = {"api_key": global_api_key, "fastCheck": "true", "emails": [email]}
    try:
        req = requests.post(url, headers=headers, json=data, cookies=global_cookies)
        response_json = req.json()
        new_credit = str(response_json.get("new_credit", "N/A"))
        new_creditt = int(response_json.get("new_credit", 0))
    except (ValueError, KeyError, requests.RequestException) as e:
        print(f"Exception occurred during email check: {e}")
        return jsonify({'email': email, 'status': 'Error', 'credit': 'N/A', 'By': 'tle:@waawx'})

    if '"status":"Die"' in req.text:
        result = {'email': email, 'status': 'available', 'credit': new_credit, 'By': 'tle:@waawx'}
        print(f'Good {email}')
    elif '"status":"live"' in req.text:
        result = {'email': email, 'status': 'Unavailable', 'credit': new_credit, 'By': 'tle:@waawx'}
        print(f'Bad {email}')
    else:
        result = {'email': email, 'status': 'Error', 'credit': new_credit, 'By': 'tle:@waawx'}
        print(f'Error {email}')
    check_and_create_account()

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
