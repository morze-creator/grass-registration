


Discover the latest moves in my Telegram Channel:

[![My Channel 🥰](https://img.shields.io/badge/morze_|_Subscribe_🥰-0A66C2?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/morze_crypto) 

### What can this bot do?
   - Registration and instant email confirmation via code.
   - Linking and verifying wallets from a file.

# 🔹Grass Registration🔹

![image](https://github.com/user-attachments/assets/cf4b8b45-0c5d-4c65-8065-6424e78e8f0b)

### Quick Start 📚
   1. To install libraries on Windows click on `INSTALL.bat`.
   2. To start bot use `START.bat`.

### Options 📧

#### 1. CREATE ACCOUNTS:
 - In `data/config.py`:
```plaintext
REGISTER_ACCOUNT_ONLY = True
CONNECT_WALLET_AND_APPROVE = False
```
 - Throw the api key into `data/config.py`. Since there is a captcha there, you need a service for solving captchas - [AntiCaptcha](http://getcaptchasolution.com/t8yfysqmh3) or [Twocaptcha](https://2captcha.com/?from=12939391):
```plaintext
TWO_CAPTCHA_API_KEY = ''
ANTICAPTCHA_API_KEY = ''
```
 - Provide emails and proxies to register accounts as below!

  ![image](https://github.com/user-attachments/assets/0d5d088b-f1d3-4484-9d9b-31fe7696083e)

  > If you plan to use a single email for verifying all accounts, you don't need to specify a password. Instead, fill in the `SINGLE_IMAP_ACCOUNT` variable in `data/config.py`.

#### 2. APPROVE EMAILS AND WALLETS:
 - in `data/config.py`:
```plaintext
REGISTER_ACCOUNT_ONLY = False
CONNECT_WALLET_AND_APPROVE = True
```
