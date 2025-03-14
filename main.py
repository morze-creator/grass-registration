import asyncio
import ctypes
import os
import random
import sys
import traceback

import aiohttp
from art import text2art
from imap_tools import MailboxLoginError
from termcolor import colored, cprint

from better_proxy import Proxy

from core import Grass
from core.autoreger import AutoReger
from core.utils import logger, file_to_list
from core.utils.accounts_db import AccountsDB
from core.utils.exception import EmailApproveLinkNotFoundException, LoginException, RegistrationException
from core.utils.generate.person import Person
from data.config import ACCOUNTS_FILE_PATH, PROXIES_FILE_PATH, THREADS, DELAY, \
    WALLETS_FILE_PATH, SINGLE_IMAP_ACCOUNT, REGISTER_ACCOUNT_ONLY, CONNECT_WALLET_AND_APPROVE
    
from datetime import datetime, timezone


def bot_info(name: str = ""):
    cprint(text2art(name), 'green')

    if sys.platform == 'win32':
        ctypes.windll.kernel32.SetConsoleTitleW(f"{name}")

    print(
        f"{colored('sourse EnJoYeR mod by morze', color='light_yellow')} "
        f"{colored('https://t.me/+01hotxJf051mM2Vi', color='light_green')}"
    )


async def worker_task(_id, account: str, proxy: str = None, wallet: str = None, db: AccountsDB = None):
    consumables = account.split(":")[:2]
    imap_pass = None

    if len(consumables) == 1:
        email = consumables[0]
        if SINGLE_IMAP_ACCOUNT:
            password = SINGLE_IMAP_ACCOUNT.split(":")[1]
    elif len(consumables) == 2:
        email, password = consumables

    grass = None

    try:
        grass = Grass(_id, email, password, proxy, db)

        delay = random.uniform(*DELAY)  # Генерируем случайную задержку
        logger.info(f"Waiting for {delay:.2f} seconds before starting №{_id}")  # Вывод времени ожидания
        await asyncio.sleep(delay)
        logger.info(f"Starting №{_id} | {email}")

        if REGISTER_ACCOUNT_ONLY:
            await grass.create_account(password)
        elif CONNECT_WALLET_AND_APPROVE:
            await grass.enter_account()

            user_info = await grass.retrieve_user()

            if user_info['result']['data'].get("walletAddress"):
                logger.success(f"{grass.id} | {grass.email} wallet already linked!")
            else:
                await grass.link_wallet(wallet)
                delay = random.uniform(*DELAY)
                logger.info(f"Waiting for {delay:.2f} seconds...")
                await asyncio.sleep(delay)

            if user_info['result']['data'].get("isWalletAddressVerified"):
                logger.success(f"{grass.id} | {grass.email} wallet already verified!")
            else:
                now = datetime.now(timezone.utc)
                await asyncio.sleep(2)
                logger.info(f"{grass.id} | {grass.email} Sending wallet confirmation email...")
                await grass.send_approve_link(endpoint="sendWalletAddressEmailVerification")
                delay = random.uniform(*DELAY)
                logger.info(f"Waiting for {delay:.2f} seconds...")
                await asyncio.sleep(delay)
                
                if password is None:
                    raise TypeError("IMAP password is not provided")
                await grass.confirm_wallet_by_email(password, now)
                
        return True
    except (LoginException, RegistrationException) as e:
        logger.warning(f"{_id} | {e}")
    except MailboxLoginError as e:
        logger.error(f"{_id} | {e}")
    # except NoProxiesException as e:
    #     logger.warning(e)
    except EmailApproveLinkNotFoundException as e:
        logger.warning(e)
    except aiohttp.ClientError as e:
        logger.warning(f"{_id} | Some connection error: {e}...")
    except Exception as e:
        logger.error(f"{_id} | not handled exception | error: {e} {traceback.format_exc()}")
    finally:
        if grass:
            await grass.session.close()
            # await grass.ws_session.close()


async def main():
    accounts = file_to_list(ACCOUNTS_FILE_PATH)

    if not accounts:
        logger.warning("No accounts found!")
        return

    proxies = [Proxy.from_str(proxy).as_url for proxy in file_to_list(PROXIES_FILE_PATH)]

    threads = THREADS
    
    msg = ""

    if REGISTER_ACCOUNT_ONLY:
        msg = "__REGISTER__ MODE"
    elif CONNECT_WALLET_AND_APPROVE:
        wallets = file_to_list(WALLETS_FILE_PATH)
        if len(wallets) == 0:
            logger.error("Wallet file is empty")
            return
        elif len(wallets) != len(accounts):
            logger.error("Wallets count != accounts count")
            return

        msg = "__APPROVE__ MODE"
    else:
        logger.error("Work mode not selected.")
        return

    logger.info(msg)
    
    autoreger = AutoReger.get_accounts(
        (ACCOUNTS_FILE_PATH, PROXIES_FILE_PATH, WALLETS_FILE_PATH),
        with_id=True
    )

    await autoreger.start(worker_task, threads)


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        if not True:
            import interface
            interface.start_ui()
        else:
            bot_info("GRASS_AUTO")
            loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(main())
    else:
        bot_info("GRASS_AUTO")

        asyncio.run(main())
