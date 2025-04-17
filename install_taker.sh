#!/bin/bash

# Set project directory
PROJECT_DIR=~/taker_quest
echo "Creating project directory: $PROJECT_DIR"
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

# Install Python and venv
echo "Installing Python and venv..."
sudo apt update
sudo apt install -y python3 python3-venv

# Create and activate virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install requests==2.32.3 urllib3==2.2.3 colorlog==6.9.0 fake-useragent==1.5.1 eth-account==0.13.6

# Create private_keys.txt (empty with instructions)
echo "Creating private_keys.txt..."
cat > private_keys.txt << EOL
# Add one Ethereum private key (64 characters, no 0x) per line
# Example:
# abc123...def456
# 789xyz...ghi012
EOL

# Create proxies.txt (empty with instructions)
echo "Creating proxies.txt..."
cat > proxies.txt << EOL
# Add one proxy (http://IP:PORT or socks5://IP:PORT) per line, matching private keys
# Example:
# http://192.168.1.1:8080
# socks5://10.0.0.1:1080
# Leave empty for no proxy
EOL

# Create taker_checkin.py
echo "Creating taker_checkin.py..."
cat > taker_checkin.py << 'EOL'
import time
import logging
import random
import re
import sys
from datetime import datetime
from colorlog import ColoredFormatter
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fake_useragent import UserAgent
from eth_account import Account
from eth_account.messages import encode_defunct
import os

# Configure colored logging
formatter = ColoredFormatter(
    "%(log_color)s%(asctime)s | %(levelname)-8s | %(message)s",
    log_colors={'INFO': 'blue', 'WARNING': 'yellow', 'ERROR': 'red', 'SUCCESS': 'green'}
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.getLogger().handlers = []
logging.getLogger().addHandler(handler)
logging.getLogger().addHandler(logging.FileHandler('checkin.log'))
logging.getLogger().setLevel(logging.INFO)
logger = logging.getLogger()
logging.addLevelName(25, 'SUCCESS')

def success(self, message, *args, **kwargs):
    self._log(25, message, args, **kwargs)
logging.Logger.success = success

# Configuration
ua = UserAgent()
API_BASE_URL = 'https://sowing-api.taker.xyz'
MAX_RETRIES = 5
REFERRAL_CODE = 'AMX46BT1'
WALLET_DELAY = 10

# Task answers
TASK_ANSWERS = [
    {"taskEventId": 1, "answer": "C"},
    {"taskEventId": 2, "answer": "A"},
    {"taskEventId": 3, "answer": "D"}
]

def read_file_lines(filename):
    if not os.path.exists(filename):
        logger.error(f"File {filename} does not exist")
        return []
    with open(filename, 'r') as f:
        return [line.strip() for line in f if not line.startswith('#')]

def extract_proxy_ip(proxy):
    if not proxy:
        return "Direct"
    match = re.search(r'(?:(?:http|socks5)://)?(?:[^@]+@)?([\d.]+:\d+)', proxy)
    return match.group(1) if match else proxy

def get_random_headers():
    resolutions = ['1920x1080', '1366x768', '1440x900', '1280x720']
    languages = ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'zh-CN,zh;q=0.9']
    return {
        'accept': 'application/json, text/plain, */*',
        'accept-language': random.choice(languages),
        'content-type': 'application/json',
        'sec-ch-ua': '"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'Referer': 'https://sowing.taker.xyz/',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'User-Agent': ua.random,
        'X-Screen-Resolution': random.choice(resolutions),
    }

def shorten_address(address):
    return f"{address[:6]}...{address[-4:]}"

# Initialize wallets
wallets = []
private_keys = read_file_lines('private_keys.txt')
proxies = read_file_lines('proxies.txt')
if not private_keys:
    logger.error("No private keys found, exiting")
    exit(1)
for i, key in enumerate(private_keys):
    try:
        account = Account.from_key(key)
        proxy = proxies[i] if i < len(proxies) and proxies[i] else None
        wallets.append({
            'account_id': f"Account{i+1}",
            'private_key': key,
            'address': account.address,
            'proxy': proxy,
            'proxy_ip': extract_proxy_ip(proxy),
            'status': 'Unauthenticated',
            'points': 0,
            'next_timestamp': 0,
            'answered': False,
            'claimed': False
        })
    except Exception as e:
        logger.error(f"Invalid private key {key[:6]}...: {str(e)}")

def api_request(wallet, url, method='GET', data=None, auth_token=None, retries=MAX_RETRIES):
    session = requests.Session()
    retries_strategy = Retry(total=retries, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries_strategy))
    headers = get_random_headers()
    if auth_token:
        headers['authorization'] = f'Bearer {auth_token}'
    for attempt in range(retries + 1):
        try:
            kwargs = {'headers': headers, 'timeout': 10}
            if data:
                kwargs['json'] = data
            if wallet['proxy']:
                kwargs['proxies'] = {'http': wallet['proxy'], 'https': wallet['proxy']}
            response = session.request(method, url, **kwargs)
            response.raise_for_status()
            if not response.text:
                return None
            try:
                data = response.json()
            except ValueError as e:
                logger.warning(f"JSON parse error: {str(e)}, status: {response.status_code}, response: {response.text[:100]}")
                raise Exception(f"JSON parse error: {str(e)}, status: {response.status_code}")
            if data.get('code') != 200:
                error_msg = data.get('message', 'Unknown error')
                if 'Rewards cannot be claimed repeatedly' in error_msg:
                    wallet['claimed'] = True
                    logger.info(f"Already claimed, marked as completed")
                    return None
                if 'Tasks cannot be repeated' in error_msg or 'task is not exist' in error_msg:
                    wallet['answered'] = True
                    logger.info(f"Task already answered or does not exist, marked as answered")
                    return None
                raise Exception(f"Request failed: {error_msg}, status: {response.status_code}")
            return data['result']
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.warning(f"Rate limit (HTTP 429), waiting 30s")
                time.sleep(30)
                continue
            if attempt < retries:
                logger.warning(f"Request failed (attempt {attempt+1}/{retries}): {str(e)}, status: {e.response.status_code}")
                time.sleep(1)
                continue
            raise Exception(f"Request failed: {str(e)}, status: {e.response.status_code if e.response else 'unknown'}")
        except Exception as e:
            if attempt < retries:
                logger.warning(f"Request failed (attempt {attempt+1}/{retries}): {str(e)}")
                time.sleep(1)
                continue
            raise Exception(f"Request failed: {str(e)}")
        finally:
            session.close()

def generate_nonce(wallet):
    result = api_request(wallet, f"{API_BASE_URL}/wallet/generateNonce", 'POST', {'walletAddress': wallet['address']})
    if isinstance(result, dict) and result.get('nonce'):
        return result['nonce']
    elif isinstance(result, str):
        nonce_match = result.split('Nonce: ')[-1].strip() if 'Nonce: ' in result else None
        if nonce_match:
            return nonce_match
    raise Exception("Failed to generate nonce")

def login(wallet, nonce):
    message = f"Taker quest needs to verify your identity to prevent unauthorized access. Please confirm your sign-in details below:\n\naddress: {wallet['address']}\n\nNonce: {nonce}"
    message_hash = encode_defunct(text=message)
    signed_message = Account.sign_message(message_hash, private_key=wallet['private_key'])
    signature = signed_message.signature.hex()
    login_data = {
        'address': wallet['address'],
        'signature': signature,
        'message': message,
        'start': REFERRAL_CODE
    }
    result = api_request(wallet, f"{API_BASE_URL}/wallet/login", 'POST', login_data)
    return result['token']

def get_user_info(wallet, token):
    return api_request(wallet, f"{API_BASE_URL}/user/info", 'GET', auth_token=token)

def perform_sign_in(wallet, token):
    return api_request(wallet, f"{API_BASE_URL}/task/signIn?status=true", 'GET', auth_token=token)

def check_task_status(wallet, token):
    url = f"{API_BASE_URL}/task/detail?walletAddress={wallet['address']}&taskId=6"
    result = api_request(wallet, url, 'GET', auth_token=token)
    task_status = result.get('taskStatus', 0)
    return task_status, result

def verify_task(wallet, token):
    logger.info(f"Starting task verification")
    for answer in TASK_ANSWERS:
        data = {
            "taskId": 6,
            "taskEventId": answer['taskEventId'],
            "answerList": [answer['answer']]
        }
        result = api_request(wallet, f"{API_BASE_URL}/task/check", 'POST', data, auth_token=token)
        if result is None:
            break
    logger.success(f"Task verification completed")

def claim_reward(wallet, token):
    logger.info(f"Claiming points and NFT")
    url = f"{API_BASE_URL}/task/claim-reward?taskId=6"
    user_info_before = get_user_info(wallet, token)
    points_before = user_info_before.get('takerPoints', 0)
    result = api_request(wallet, url, 'POST', {}, auth_token=token)
    user_info_after = get_user_info(wallet, token)
    points_after = user_info_after.get('takerPoints', 0)
    if points_after >= points_before + 200:
        wallet['claimed'] = True
        logger.success(f"Claim successful, points: {points_before} -> {points_after}")
    elif result is not None:
        logger.success(f"Claim successful: {result}, points: {points_before} -> {points_after}")
    elif wallet['claimed']:
        logger.info(f"Already claimed, points: {points_before} -> {points_after}")
    else:
        logger.warning(f"Claim failed, points: {points_before} -> {points_after}")
    return result

def format_time_remaining(timestamp):
    now = datetime.now().timestamp() * 1000
    time_left = timestamp - now
    if time_left <= 0:
        return "Ready to sign in"
    hours = int(time_left // (1000 * 60 * 60))
    minutes = int((time_left % (1000 * 60 * 60)) // (1000 * 60))
    seconds = int((time_left % (1000 * 60)) // 1000)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

class TakerBot:
    def __init__(self):
        self.tokens = {}

    def process_wallet(self, wallet, index, total_wallets):
        logger.info(f"Processing {index+1}/{total_wallets} | {wallet['account_id']} | {shorten_address(wallet['address'])} | Proxy: {wallet['proxy_ip']}")
        try:
            if wallet['address'] not in self.tokens:
                nonce = generate_nonce(wallet)
                token = login(wallet, nonce)
                self.tokens[wallet['address']] = token
                logger.success(f"Login successful")
            user_info = get_user_info(wallet, self.tokens[wallet['address']])
            wallet['points'] = user_info.get('takerPoints', 0)
            if user_info.get('nextTimestamp', 0) > datetime.now().timestamp() * 1000:
                wallet['status'] = 'Active'
                wallet['next_timestamp'] = user_info['nextTimestamp']
                logger.info(f"Already signed in, points: {wallet['points']}, time left: {format_time_remaining(wallet['next_timestamp'])}")
            else:
                perform_sign_in(wallet, self.tokens[wallet['address']])
                user_info = get_user_info(wallet, self.tokens[wallet['address']])
                wallet['points'] = user_info.get('takerPoints', 0)
                wallet['status'] = 'Active'
                wallet['next_timestamp'] = user_info.get('nextTimestamp', 0)
                logger.success(f"Sign-in successful, points: {wallet['points']}")
            task_status, task_details = check_task_status(wallet, self.tokens[wallet['address']])
            if wallet['points'] >= 300:
                wallet['claimed'] = True
                wallet['answered'] = True
            if task_status >= 1 or wallet['answered'] or wallet['claimed']:
                logger.info(f"Task or claim already completed, skipping")
                return user_info, True
            verify_task(wallet, self.tokens[wallet['address']])
            wallet['answered'] = True
            claim_reward(wallet, self.tokens[wallet['address']])
            user_info = get_user_info(wallet, self.tokens[wallet['address']])
            wallet['points'] = user_info.get('takerPoints', 0)
            logger.success(f"All tasks completed, current points: {wallet['points']}")
            return user_info, True
        except Exception as e:
            wallet['status'] = f'Failed: {str(e)}'
            logger.error(f"Operation failed: {str(e)}")
            return None, False
        finally:
            time.sleep(WALLET_DELAY + random.uniform(0, 3))

    def display_status(self):
        logger.info("Current status:")
        for wallet in wallets:
            logger.info(f"{shorten_address(wallet['address'])} | Points: {wallet['points']} | Status: {wallet['status']} | Time left: {format_time_remaining(wallet['next_timestamp']) if wallet['next_timestamp'] else 'Ready to sign in'} | Answered: {wallet['answered']} | Claimed: {wallet['claimed']}")

    def cleanup(self):
        logger.info("Cleaning up and exiting...")
        logger.info("Final status:")
        for wallet in wallets:
            logger.info(f"{wallet['account_id']} | {shorten_address(wallet['address'])} | Points: {wallet['points']} | Status: {wallet['status']} | Time left: {format_time_remaining(wallet['next_timestamp']) if wallet['next_timestamp'] else 'Ready to sign in'} | Answered: {wallet['answered']} | Claimed: {wallet['claimed']}")
        logger.info("Bot exited, logs saved to checkin.log")

    def run(self):
        total_wallets = len(wallets)
        logger.info(f"Starting Taker Bot, processing {total_wallets} wallets")
        try:
            while True:
                failed_wallets = []
                for i, wallet in enumerate(wallets):
                    user_info, success = self.process_wallet(wallet, i, total_wallets)
                    if not success:
                        failed_wallets.append(wallet)
                    logger.info("")
                if failed_wallets:
                    logger.info(f"Retrying {len(failed_wallets)} failed wallets")
                    for i, wallet in enumerate(failed_wallets[:]):
                        user_info, success = self.process_wallet(wallet, i, len(failed_wallets))
                        if success:
                            failed_wallets.remove(wallet)
                        logger.info("")
                self.display_status()
                logger.info(f"All wallets processed, waiting 300s before next round...")
                time.sleep(300)
        except KeyboardInterrupt:
            self.cleanup()
            sys.exit(0)

if __name__ == "__main__":
    bot = TakerBot()
    bot.run()
EOL

# Set permissions
chmod +x taker_checkin.py

# Deactivate virtual environment
deactivate

echo "Installation complete!"
echo "Files created: private_keys.txt, proxies.txt, taker_checkin.py"
echo "To run the script:"
echo "  cd $PROJECT_DIR"
echo "  source venv/bin/activate"
echo "  python taker_checkin.py"
echo "Edit private_keys.txt to add your private keys before running."
