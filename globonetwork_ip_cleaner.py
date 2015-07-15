import mysql.connector
import logging
from prettytable import PrettyTable
from ACSConn import CloudStack
from colors import Colors
import argparse
import os
import sys
import time
import traceback
from ConfigParser import SafeConfigParser
from my_email import MyEmail

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)
LOG = logging.getLogger(__name__)

DB_DATABASE = "cloud"


class GloboNetworkIpCleaner(object):
    def __init__(self, options={}):

        self.db_host = options.get("db_host")
        self.db_user = options.get("db_user")
        self.db_password = options.get("db_password")
        self.db_database = DB_DATABASE
        self.db_connection = None
        self.api = options.get("api")
        self.table_expunging_ips = PrettyTable(["IP", "STATE", "REMOVED"])
        self._region = options.get("region", "")


        # email
        self.send_email = options.get("send_mail", False)
        self.email_to = options.get("email_to", "")
        self.email_from = options.get("email_from", "")
        self._email_body = []
        self._email_subject = options.get("email_subject",
                                          "[CLOUDSTACK GLOBONETWORK IP CLEANER %s] - zumbi volume found!" % self._region)


    def open_connection(self):
        self.db_connection = mysql.connector.connect(user=self.db_user, password=self.db_password,
                                                     host=self.db_host,
                                                     database=self.db_database)

    def close_connection(self):
        try:
            self.db_connection.close()
        except:
            pass


    def get_expunging_ips(self):

        query = ("SELECT x.private_ip_address, x.state, x.removed "
                 "FROM cloud.vm_instance x "
                 "WHERE state = 'Expunging' and removed is null")

        self.open_connection()
        cursor = self.db_connection.cursor()
        cursor.execute(query)
        result = []
        for (private_ip_address, state, removed) in cursor:
            result.append((private_ip_address, state, removed))

        cursor.close()
        self.close_connection()

        return result


    def notify_email(self):
        self._email_body.append(self.table_expunging_ips.get_html_string())
        body = "<br/>".join(self._email_body)
        my_email = MyEmail(to=self.email_to,
                           from_=self.email_from,
                           subject=self._email_subject,
                           body=body)
        my_email.send()


    def run(self):
        results = self.get_expunging_ips()
        LOG.debug(results)

        print self.table_expunging_ips



if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Volume Monitor')
    parser.add_argument('--region', type=str, default='lab',
                        help='Choose your region based on your cloudmonkey profile. Default profile is "lab"')
    parser.add_argument('--send_email', type=bool, default=False,
                        help='Should we send email? (Default false)')
    parser.add_argument('--email_to', type=str, default='',
                        help='Send email to')
    parser.add_argument('--email_from', type=str, default='',
                        help='Who is sending the email?')
    args = parser.parse_args()


    # import keys from cloudmonkey config
    parser = SafeConfigParser()
    parser.read(os.path.expanduser('~/.cloudmonkey/config'))
    if parser.has_section(args.region):
        if not parser.has_option(args.region, 'url'):
            sys.exit("There is no url option in '%s' section" % args.region)
        if not parser.has_option(args.region, 'apikey'):
            sys.exit("There is no 'apikey' option in '%s' section" % args.region)
        if not parser.has_option(args.region, 'secretkey'):
            sys.exit("There is no 'secretkey' option in '%s' section" % args.region)
        if not parser.has_option(args.region, 'db_host'):
            sys.exit("There is no 'db_host' option in '%s' section" % args.region)
        if not parser.has_option(args.region, 'db_user'):
            sys.exit("There is no 'db_user' option in '%s' section" % args.region)
        if not parser.has_option(args.region, 'db_password'):
            sys.exit("There is no 'db_password' option in '%s' section" % args.region)
        if not parser.has_option(args.region, 'networkapi_url'):
            sys.exit("There is no 'networkapi_url' option in '%s' section" % args.region)
        if not parser.has_option(args.region, 'networkapi_username'):
            sys.exit("There is no 'networkapi_username' option in '%s' section" % args.region)
        if not parser.has_option(args.region, 'networkapi_password'):
            sys.exit("There is no 'networkapi_password' option in '%s' section" % args.region)

        apikey = parser.get(args.region, 'apikey')
        api_url = parser.get(args.region, 'url')
        secretkey = parser.get(args.region, 'secretkey')
        verifysslcert = parser.getboolean(args.region, 'verifysslcert')

        db_host = parser.get(args.region, 'db_host')
        db_user = parser.get(args.region, 'db_user')
        db_password = parser.get(args.region, 'db_password')

        networkapi_url = parser.get(args.region, 'networkapi_url')
        networkapi_username = parser.get(args.region, 'networkapi_username')
        networkapi_password = parser.get(args.region, 'networkapi_password')

    else:
        sys.exit("Invalid region: '%s'" % args.region)

    send_email = args.send_email
    email_to = ""
    email_from = ""
    if send_email:
        email_to = args.email_to
        email_from = args.email_from
        if not email_from:
            LOG.warning("You did not specify the email_from option")
            sys.exit(1)

    api = CloudStack(api_url, apikey, secretkey, verifysslcert)
    options = {"api": api,
               "db_host": db_host,
               "db_user": db_user,
               "db_password": db_password,
               "send_mail": send_email,
               "email_to": email_to,
               "email_from": email_from,
               "region": args.region}

    ip_cleaner = GloboNetworkIpCleaner(options=options)
    ip_cleaner.run()