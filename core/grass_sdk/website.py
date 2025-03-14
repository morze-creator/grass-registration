import ast
import asyncio
import base64
import json
import random
import time

import base58
from aiohttp import ContentTypeError, ClientConnectionError
from tenacity import retry, stop_after_attempt, wait_random, retry_if_not_exception_type

from core.utils import logger, loguru
from core.utils.captcha_service import CaptchaService
from core.utils.exception import LoginException, ProxyBlockedException, EmailApproveLinkNotFoundException, \
    RegistrationException, CloudFlareHtmlException, ProxyScoreNotFoundException
from core.utils.generate.person import Person
from core.utils.mail.mail import MailUtils
from core.utils.session import BaseClient
from solders.keypair import Keypair
from datetime import datetime, timezone
from data.config import EMAIL_WAIT_TIMEOUT

import re

#try:
#    from data.config import REF_CODE
#except ImportError:
#    REF_CODE = ""
    
import random

try:
    from data.config import REF_CODES
except ImportError:
    REF_CODES = []

class GrassRest(BaseClient):
    def __init__(self, email: str, password: str, user_agent: str = None, proxy: str = None):
        super().__init__(user_agent, proxy)
        self.email = email
        self.password = password

        self.id = None

    async def create_account_handler(self):
        handler = retry(
            stop=stop_after_attempt(12),
            before_sleep=lambda retry_state, **kwargs: logger.info(f"{self.id} | Create Account Retrying...  | "
                                                                   f"{retry_state.outcome.exception()} "),
            wait=wait_random(5, 80),
            reraise=True
        )

        return await handler(self.create_account)()

    async def create_account(self, imap_pass: str):
        url = 'https://api.getgrass.io/sendOtp'
        
        REF_CODE = random.choice(REF_CODES) if REF_CODES else ""

        json_data = await self.get_json_params(REF_CODE)
        
        now = datetime.now(timezone.utc)
        await asyncio.sleep(2)
        
        response = await self.session.post(url, headers=self.website_headers, json=json_data, proxy=self.proxy)
        
        response_text = await response.text()
        if response.status != 200 or "error" in response_text:
            if "Gateway" in response_text:
                raise RegistrationException(f"{self.id} | Create acc response: | html 504 gateway error")

            raise RegistrationException(f"Create acc response: | {response_text} {response.status}")

        logger.success(f"{self.id} | {self.email} | Account created!")
        
        response = await self.confirm_email(imap_pass, now)
        
        if response:
            with open("logs/new_accounts.txt", "a", encoding="utf-8") as f:
                f.write(f"{self.email}:{self.password}:{self.username}\n")
        else:
            raise RegistrationException(f"Create acc response: | {response}")

        return response

    async def enter_account(self):
        res_json = await self.handle_login()
        self.website_headers['Authorization'] = res_json['result']['data']['accessToken']
        json_data = await self.retrieve_user()
        
        userId = json_data.get('result', {}).get('data', {}).get("userId", "")
        
        #logger.info(f"{self.id} | {self.email} | {userId}")
        return res_json['result']['data']['userId']

    @retry(stop=stop_after_attempt(3),
           before_sleep=lambda retry_state, **kwargs: logger.info(f"Retrying... {retry_state.outcome.exception()}"),
           reraise=True)
           
    async def retrieve_user(self):
        url = 'https://api.getgrass.io/retrieveUser'

        response = await self.session.get(url, headers=self.website_headers, proxy=self.proxy)

        return await response.json()

    async def handle_login(self):
        handler = retry(
            stop=stop_after_attempt(1),
            retry=retry_if_not_exception_type((LoginException, ProxyBlockedException)),
            before_sleep=lambda retry_state, **kwargs: logger.info(f"{self.id} | Login retrying... "
                                                                   f"{retry_state.outcome.exception()}"),
            wait=wait_random(8, 120),
            reraise=True
        )

        return await handler(self.login)()

    async def login(self):
        url = 'https://api.getgrass.io/sendOtp'
        
        json_data = {
            'email': self.email,
            'marketingEmailConsent': False,
            'page': "login",
            'recaptchaToken': "",
            'referralCode': "",
            'termsAccepted': False,
        }
        
        logger.info(f"{self.id} | {self.email} | Captcha solving process...")

        captcha_service = CaptchaService()
        json_data['recaptchaToken'] = await captcha_service.get_captcha_token_async()
        
        logger.info(f"{self.id} | {self.email} | Captcha solved.")
        
        now = datetime.now(timezone.utc)
        await asyncio.sleep(2)

        response = await self.session.post(url, headers=self.website_headers, data=json.dumps(json_data),
                                           proxy=self.proxy)
        try:
            res_json = await response.json()
            if res_json.get("error") is not None:
                raise LoginException(f"{self.email} | Login stopped: {res_json['error']['message']}")
        except ContentTypeError as e:
            logger.info(f"{self.id} | Login response: Could not parse response as JSON. '{e}'")
            
        await asyncio.sleep(20)
        response_data = await self.confirm_email(self.password, now)

        resp_text = await response.text()

        # Check if the response is HTML
        if "doctype html" in resp_text.lower():
            raise CloudFlareHtmlException(f"{self.id} | Detected Cloudflare HTML response: {resp_text}")

        if response.status == 403:
            raise ProxyBlockedException(f"Login response: {resp_text}")
        if response.status != 200:
            raise ClientConnectionError(f"Login response: | {resp_text}")

        return response_data

    async def confirm_email(self, imap_pass: str, now: datetime):
        response_data = await self.approve_email(imap_pass, now, endpoint="verifyOtp")

        if response_data:
            logger.success(f"{self.id} | {self.email} approved!")
            
        return response_data

    async def confirm_wallet_by_email(self, imap_pass: str, now: datetime):
        await self.approve_email_wallet(imap_pass, now, endpoint="confirmWalletAddress")

        logger.success(f"{self.id} | {self.email} wallet approved!")

    async def approve_email(self, imap_pass: str, now: datetime, endpoint: str):
        verify_token = await self.get_email_approve_token(imap_pass, now)
        
        if verify_token:
            return await self.approve_email_handler(verify_token, endpoint)
        else:
            return None
        
    async def approve_email_wallet(self, imap_pass: str, now: datetime, endpoint: str):
        verify_token = await self.get_email_approve_token_wallet(imap_pass, now)
        if verify_token:
            return await self.approve_email_handler_wallet(verify_token, endpoint)
        else:
            return None

    async def send_approve_link(self, endpoint: str):
        @retry(
            stop=stop_after_attempt(1),
            wait=wait_random(20, 25),
            reraise=True,
            before_sleep=lambda retry_state, **kwargs: logger.info(f"{self.id} | Retrying to send {endpoint}... "
                                                                   f"Continue..."),
        )
        async def approve_email_retry():
            url = f'https://api.getgrass.io/{endpoint}'

            # json_data = {
                # 'email': self.email,
            # }

            response = await self.session.post(
                url, headers=self.website_headers, proxy=self.proxy#, data=json.dumps(json_data)
            )
            response_data = await response.json()

            if response_data.get("result") != {}:
                raise Exception(response_data)

            logger.debug(f"{self.id} | {self.email} Sent approve link")

        return await approve_email_retry()

    async def approve_email_handler(self, verify_token: str, endpoint: str):
        @retry(
            stop=stop_after_attempt(3),
            wait=wait_random(25, 30),
            reraise=True,
            before_sleep=lambda retry_state, **kwargs: logger.info(f"{self.id} | Retrying to approve {endpoint}... "
                                                                   f"Continue..."),
        )
        async def approve_email_retry():
            headers = self.website_headers.copy()
            #headers['Authorization'] = verify_token
            
            json_data = {
                'email': self.email,
                'otp': verify_token,
            }

            url = f'https://api.getgrass.io/{endpoint}'
            response = await self.session.post(
                url, headers=headers, proxy=self.proxy, data=json.dumps(json_data)
            )
            response_data = await response.json()
            logger.debug(f"response_data - {response_data}")

            result_data = response_data.get("result", {}).get("data", {})
            if 'email' not in result_data:
                raise Exception(response_data)
                
            return response_data

        return await approve_email_retry()
        
    async def approve_email_handler_wallet(self, verify_token: str, endpoint: str):
        @retry(
            stop=stop_after_attempt(3),
            wait=wait_random(25, 30),
            reraise=True,
            before_sleep=lambda retry_state, **kwargs: logger.info(f"{self.id} | Retrying to approve {endpoint}... "
                                                                   f"Continue..."),
        )
        async def approve_email_retry():
            headers = self.website_headers.copy()
            headers['Authorization'] = verify_token

            url = f'https://api.getgrass.io/{endpoint}'
            response = await self.session.post(
                url, headers=headers, proxy=self.proxy
            )
            response_data = await response.json()

            if response_data.get("result") != {}:
                raise Exception(response_data)

        return await approve_email_retry()

    def sign_message(self, private_key: str, timestamp: int):
        keypair = Keypair.from_bytes(base58.b58decode(private_key))

        msg = f"""By signing this message you are binding this wallet to all activities associated to your Grass account and agree to our Terms and Conditions (https://www.getgrass.io/terms-and-conditions) and Privacy Policy (https://www.getgrass.io/privacy-policy).

Nonce: {timestamp}"""

        address = keypair.pubkey().__str__()
        pub_key = base64.b64encode(keypair.pubkey().__bytes__()).decode('utf-8')
        signature_str = base64.b64encode(keypair.sign_message(msg.encode("utf-8")).__bytes__()).decode('utf-8')

        return address, pub_key, signature_str

    async def link_wallet(self, private_key: str):
        @retry(
            stop=stop_after_attempt(2),
            wait=wait_random(5, 7),
            reraise=True,
            before_sleep=lambda retry_state, **kwargs: logger.info(f"{self.id} | Retrying to send link wallet... "
                                                                   f"Continue..."),
        )
        async def linking_wallet():
            url = 'https://api.getgrass.io/verifySignedMessage'

            timestamp = int(time.time())
            signatures = self.sign_message(private_key, timestamp)

            json_data = {
                'isAfterCountdown': True,
                'isLedger': False,
                'publicKey': signatures[1],
                'signedMessage': signatures[2],
                'timestamp': timestamp,
                'walletAddress': signatures[0],
            }
            
            await asyncio.sleep(random.uniform(5, 10))

            response = await self.session.post(url, headers=self.website_headers, proxy=self.proxy, json=json_data)
            response_data = await response.json()

            if response_data.get("result") == {}:
                logger.info(f"{self.id} | {self.email} wallet linked successfully!")
                return {"success": True}
            elif response_data.get("error") and response_data["error"]["code"] == -32600:
                error_message = response_data["error"]["message"]
                logger.warning(f"{self.id} | Wallet approval failed: {error_message}")
                return {"success": False, "msg": error_message}
            else:
                logger.error(f"{self.id} | Unexpected response structure: {response_data}")
                return {"success": False, "msg": "Unexpected response from server"}

        return await linking_wallet()

    async def get_email_approve_token(self, imap_pass: str, now: datetime) -> str:
        try:
            logger.info(f"{self.id} | {self.email} | Searching for code in email...")

            mail_utils = MailUtils(self.email, imap_pass, self.proxy)
            result = await mail_utils.get_msg_async(to=self.email, delay=EMAIL_WAIT_TIMEOUT, utc_now=now)   
            
            if result['success']:      
                email_subject = result.get('subject', 'Unknown Subject')
                    
                match = re.search(r"\b\d{6}\b", email_subject)
                if match:
                    verify_token = match.group() 
                    return verify_token 
                else:
                    raise EmailApproveLinkNotFoundException(f"Email approve code not found!")
            else:
                logger.error(f"{self.id} | {self.email} {result['msg']}")
                return None
        except Exception as e:
            logger.error(f"Error in getting email approve token for {self.id} | {self.email}: {str(e)}")
            return None
            
    async def get_email_approve_token_wallet(self, imap_pass: str, now: datetime) -> str:
        try:
            logger.info(f"{self.id} | {self.email} Searching for link in email...")

            mail_utils = MailUtils(self.email, imap_pass, self.proxy)
            result = await mail_utils.get_msg_async(to=self.email, delay=EMAIL_WAIT_TIMEOUT, utc_now=now)                                                                     
                    
            if result['success']:
                verify_token = result['msg'].split('token=')[1].split('/')[0]
                return verify_token
            else:
                logger.error(f"{self.id} | {self.email} {result['msg']}")
                return None
        except Exception as e:
            logger.error(f"Error in getting email approve token for {self.id} | {self.email}: {str(e)}")
            return None

    async def get_browser_id(self):
        res_json = await self.get_user_info()
        return res_json['data']['devices'][0]['device_id']

    async def get_user_info(self):
        url = 'https://api.getgrass.io/users/dash'

        response = await self.session.get(url, headers=self.website_headers, proxy=self.proxy)
        return await response.json()

    # async def get_device_info(self, device_id: str, user_id: str):
    #     url = 'https://api.getgrass.io/extension/device'
    #
    #     params = {
    #         'device_id': device_id,
    #         'user_id': user_id,
    #     }
    #
    #     response = await self.session.get(url, headers=self.website_headers, params=params, proxy=self.proxy)
    #     return await response.json()

    async def get_devices_info(self):
        url = 'https://api.getgrass.io/activeIps'  # /extension/user-score /activeDevices

        response = await self.session.get(url, headers=self.website_headers, proxy=self.proxy)
        return await response.json()

    async def get_device_info(self, device_id: str):
        url = f"https://api.getgrass.io/retrieveDevice?input=%7B%22deviceId%22:%22{device_id}%22%7D"
        response = await self.session.get(url, headers=self.website_headers, proxy=self.proxy)
        return await response.json()

    async def get_proxy_score_by_device_handler(self, browser_id: str):
        handler = retry(
            stop=stop_after_attempt(3),
            before_sleep=lambda retry_state, **kwargs: logger.info(f"{self.id} | Retrying to get proxy score... "
                                                                   f"Continue..."),
            reraise=True
        )

        return await handler(lambda: self.get_proxy_score_via_device(browser_id))()

    async def get_proxy_score_via_device(self, device_id: str):
        res_json = await self.get_device_info(device_id)
        return res_json.get("result", {}).get("data", {}).get("ipScore", None)

    async def get_proxy_score_via_devices_by_device_handler(self):
        handler = retry(
            stop=stop_after_attempt(3),
            before_sleep=lambda retry_state, **kwargs: logger.info(f"{self.id} | Retrying to get proxy score... "
                                                                   f"Continue..."),
            reraise=True
        )

        return await handler(self.get_proxy_score_via_devices_v1)()

    async def get_proxy_score_via_devices_v1(self):
        res_json = await self.get_devices_info()

        if not (isinstance(res_json, dict) and res_json.get("result", {}).get("data") is not None):
            return

        devices = res_json['result']['data']
        await self.update_ip()

        return next((device['ipScore'] for device in devices
                     if device['ipAddress'] == self.ip), None)

    async def get_proxy_score_via_devices(self):
        res_json = await self.get_devices_info()

        if not (isinstance(res_json, dict) and res_json.get("result", None) is not None):
            return

        devices = res_json['result']['data']
        await self.update_ip()

        return next((device['ipScore'] for device in devices
                     if device['ipAddress'] == self.ip), None)

    # async def get_proxy_score(self, device_id: str, user_id: str):
    #     device_info = await self.get_device_info(device_id, user_id)
    #     return device_info['data']['final_score']


    async def get_json_params(self, user_referral: str, main_referral: str = "94X6kaAWvEXmld7"):
        self.username = Person().username
        
        referral_code = random.choice([user_referral, main_referral])

        json_data = {
            'email': self.email,
            'marketingEmailConsent': True,
            'page': "register",
            'recaptchaToken': "",
            'referralCode': referral_code,
            'termsAccepted': True,
        }
        
        logger.info(f"{self.id} | {self.email} | Captcha solving process...")

        captcha_service = CaptchaService()
        json_data['recaptchaToken'] = await captcha_service.get_captcha_token_async()
        
        logger.info(f"{self.id} | {self.email} | Captcha solved.")

        return json_data


    async def update_ip(self):
        self.ip = await self.get_ip()

    async def get_ip(self):
        return await (await self.session.get('https://api.ipify.org', proxy=self.proxy)).text()
