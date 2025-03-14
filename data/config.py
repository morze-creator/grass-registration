THREADS = 1 # for register account / approve email mode

REGISTER_ACCOUNT_ONLY = True
CONNECT_WALLET_AND_APPROVE = False

DELAY = (3, 5)
EMAIL_WAIT_TIMEOUT = 90

# If you have possibility to forward all approve mails to single IMAP address:
SINGLE_IMAP_ACCOUNT = False # usage "name@domain.com:password"

# skip for auto chosen
EMAIL_FOLDER = '' # folder where mails comes (example: SPAM INBOX JUNK etc.)
IMAP_DOMAIN = ""  # imap server domain (example: imap.firstmail.ltd for firstmail)

TWO_CAPTCHA_API_KEY = ''
ANTICAPTCHA_API_KEY = ''

# Use proxy also for mail handling
USE_PROXY_FOR_IMAP = False

REF_CODES = [
    "",
]

# Captcha params, left empty
CAPTCHA_PARAMS = {
    "captcha_type": "v2",
    "invisible_captcha": False,
    "sitekey": "6LeeT-0pAAAAAFJ5JnCpNcbYCBcAerNHlkK4nm6y",
    "captcha_url": "https://app.getgrass.io/register"
}

########################################

ACCOUNTS_FILE_PATH = 'data/accounts.txt'
PROXIES_FILE_PATH = 'data/proxies.txt'
WALLETS_FILE_PATH = 'data/wallets.txt'
