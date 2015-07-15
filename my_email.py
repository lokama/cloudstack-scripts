import logging

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

LOG = logging.getLogger(__name__)


class MyEmail(object):

    def __init__(self, to=None, cc=None, from_="", subject="", body=""):
        self._to = to
        self._cc = cc
        self._subject = subject
        self._body = body
        self._from = from_

        self._msg = MIMEMultipart('alternative')
        self._msg['Subject'] = self._subject
        self._msg['From'] = self._from
        self._msg['To'] = self._to

        part1 = MIMEText(body, 'plain', "utf-8")
        part2 = MIMEText(body, 'html', "utf-8")

        self._msg.attach(part1)
        self._msg.attach(part2)

    def send(self):
        s = smtplib.SMTP('localhost')
        s.sendmail(self._from, [self._to], self._msg.as_string())
        s.quit()