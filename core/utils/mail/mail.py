import time
import asyncio
from typing import Optional, Dict
from imap_tools import AND
from loguru import logger
from core.utils.mail.mailbox import MailBox
from data.config import EMAIL_FOLDER, IMAP_DOMAIN, SINGLE_IMAP_ACCOUNT, USE_PROXY_FOR_IMAP
from datetime import datetime, timezone, timedelta

class MailUtils:
    def __init__(self, email: str, imap_pass: str, proxy: str = None) -> None:
        if SINGLE_IMAP_ACCOUNT:
            self.email: str = SINGLE_IMAP_ACCOUNT.split(":")[0]
        else:
            self.email: str = email

        self.imap_pass: str = imap_pass
        self.domain: str = IMAP_DOMAIN or self.parse_domain()

        self.proxy = proxy if USE_PROXY_FOR_IMAP else None

    def parse_domain(self) -> str:
        domain: str = self.email.split("@")[-1]

        if "hotmail" in domain or "live" in domain:
            domain = "outlook.com"
        elif "yahoo" in domain:
            domain = "mail.yahoo.com"
        elif "firstmail" in domain:
            domain = "firstmail.ltd"
        elif any(sub in domain for sub in ["rambler", "myrambler", "autorambler", "ro.ru"]):
            domain = "rambler.ru"
        elif "icloud" in domain:
            domain = "mail.me.com"
        elif "gazeta" in domain:
            domain = "gazeta.pl"
        elif "onet" in domain:
            domain = "poczta.onet.pl"
        elif "gmx" in domain:
            domain = "gmx.net"
        elif "firemail" in domain:
            domain = "firemail.de"
        elif "icloud" in domain:
            domain = "imap.mail.me"

        return f"imap.{domain}"

    def get_msg(
            self,
            to: Optional[str] = None,
            subject: Optional[str] = None,
            from_: Optional[str] = None,
            seen: Optional[bool] = None,
            limit: Optional[int] = None,
            reverse: bool = True,
            delay: int = 60,
            utc_now: datetime = datetime.now(timezone.utc)  # Значение по умолчанию
    ) -> Dict[str, any]:

        if EMAIL_FOLDER:
            email_folders = [EMAIL_FOLDER]
        else:
            email_folders = ["INBOX", "Junk", "JUNK", "Spam", "SPAM", "TRASH", "Trash", "Спам"]

        with MailBox(
                self.domain,
                proxy=self.proxy
        ).login(self.email, self.imap_pass, initial_folder=None) as mailbox:
            actual_folders = [mailbox.name for mailbox in list(mailbox.folder.list())]
            folders = [folder for folder in email_folders if folder in actual_folders]

            for _ in range(delay // 3):
                time.sleep(3)
                try:
                    for folder in folders:
                        mailbox.folder.set(folder)
                        if "gazeta.pl" in self.domain:
                            for msg in mailbox.fetch(limit=1, reverse=reverse):
                                if subject and subject.lower() in msg.subject.lower():
                                    return {
                                        "success": True,
                                        "msg": msg.html,
                                        "subject": msg.subject,
                                        "from": msg.from_,
                                        "to": msg.to
                                    }
                        else:
                            criteria = AND(to=to, from_=from_)
                            for msg in mailbox.fetch(criteria, limit=1, reverse=reverse):
                                if msg.date > utc_now:
                                    mailbox.flag(msg.uid, "\\Seen", True)
                                    return {
                                        "success": True,
                                        "msg": msg.html,
                                        "subject": msg.subject,
                                        "from": msg.from_,
                                        "to": msg.to
                                    }
                except Exception as error:
                    logger.error(f'{self.email} | Error when fetching new message by subject: {str(error)}')

        return {"success": False, "msg": "New message not found by subject"}

    async def get_msg_async(
            self,
            to: Optional[str] = None,
            subject: Optional[str] = None,
            from_: Optional[str] = None,
            seen: Optional[bool] = None,
            limit: Optional[int] = None,
            reverse: bool = True,
            delay: int = 60,
            utc_now: datetime = datetime.now(timezone.utc)  # Значение по умолчанию
    ) -> Dict[str, any]:
        return await asyncio.to_thread(self.get_msg, to, subject, from_, seen, limit, reverse, delay, utc_now)


# Пример использования:
# if __name__ == '__main__':
#     email = "kathyxobige@gazeta.pl"
#     imap_pass = "your_password"
#     mail_utils = MailUtils(email, imap_pass)
#
#     async def main():
#         result = await mail_utils.get_msg_async(subject="Verify Your Email for Grass")
#         print(result)
#
#     asyncio.run(main())
