


Discover the latest moves in my Telegram Channel:

[![My Channel 🥰](https://img.shields.io/badge/morze_|_Subscribe_🥰-0A66C2?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/morze_crypto) 

### What can this bot do?
   - Registration and instant email confirmation via code.
   - Linking and verifying wallets from a file.

# 🔹Grass Registration🔹

![image](https://github.com/user-attachments/assets/cf4b8b45-0c5d-4c65-8065-6424e78e8f0b)

## Quick Start 📚
   1. Clone this repository or download the archive:
```
git clone https://github.com/morze-creator/grass-registration
```
   2. To install libraries on Windows click on `INSTALL.bat`.
   3. To start bot use `START.bat`.

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

  ![image](https://github.com/user-attachments/assets/7cfee1cc-9131-4e0b-8e2e-963ca151e909)

  > If you plan to use a single email for verifying all accounts, you don't need to specify a password. Instead, fill in the `SINGLE_IMAP_ACCOUNT` variable in `data/config.py`.

#### 2. APPROVE EMAILS AND WALLETS:
 - in `data/config.py`:
```plaintext
REGISTER_ACCOUNT_ONLY = False
CONNECT_WALLET_AND_APPROVE = True
```
 - in `data/wallets.py` enter Solana private keys in Base58 format.
## Stay Connected 📒
Channel Telegram: [morze](https://t.me/morze_crypto)  
Chat Telegram: [morze CHAT](https://t.me/+2tiSWUvVHDI1OWMy)  

## Donation 💸
If you would like to support the development of this project, you can make a donation using the following addresses:

   - Solana: `EkWhh25qTN3LaToLJYJ72W2GmBtSwkQ43C2YTrXcNS6w`
   - EVM: `0x13fc513856594f14c95f6558e080c16240caC999`
   - BTC: `bc1qs8uk7kxu2tk8c0sgamwka2d99y2f53flkuswgr`

## Disclaimer ❗
This tool is for educational purposes only. Use it at your own risk.
