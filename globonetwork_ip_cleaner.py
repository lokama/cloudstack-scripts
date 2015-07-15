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
from networkapiclient.Pagination import Pagination
from networkapiclient.Equipamento import Equipamento
from networkapiclient.Ip import Ip
from networkapiclient.exception import IpNaoExisteError
from networkapiclient.Vip import Vip

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)
LOG = logging.getLogger(__name__)

DB_DATABASE = "cloud"


class NetworkApi(object):

    def __init__(self, url=None, username=None, password=None):
        self.url = url
        self.username = username
        self.password = password


class GloboNetworkIp(object):
    """
        #find the vip_id <vip_id> = Equipamento.get_real_related(<equip_id>)

        #find the ip_id <ip_id> = Ip.get_ipv4_or_ipv6('<ip>')

        #remove the real Vip.remover_real(<vip_id>, <ip_id>, <equip_id>)
    """

    def __init__(self, ip=None, state=None, removed=None, network_api=None):
        self.ip = dict(address=ip, id=None)
        self.state = state
        self.removed = removed
        self.network_api = network_api
        self.equipamento = dict(name=None, id=None, vlan=None)

        self.get_ip_id()
        self.get_equipamento()

    def get_equipamento(self):
        pagination = Pagination(0, 25, "", "", "")
        equipamento_ = Equipamento(self.network_api.url, self.network_api.username, self.network_api.password)

        result = equipamento_.find_equips(None, None, None, None, None, self.ip["address"], pagination)
        equip = result.get('equipamento',[])
        if equip:
            self.equipamento["name"] = equip[0]['nome']
            self.equipamento["id"] = equip[0]['id']
            self.equipamento["vlan"] = equip[0]['ips'][0]['vlan']

    def get_ip_id(self):
        ip_ = Ip(self.network_api.url, self.network_api.username, self.network_api.password)
        try:
            result = ip_.get_ipv4_or_ipv6(self.ip["address"])
            self.ip["id"] = result['ips']['id']
        except IpNaoExisteError, e:
            LOG.warning("ip %s not found", self.ip["address"])

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        return u"ip: %s | state: %s | removed: %s | equipamento: %s" % (self.ip, self.state, self.removed, self.equipamento)

class GloboNetworkIpCleaner(object):
    def __init__(self, options={}):

        #networkapi
        self.networkapi_url = options.get("networkapi_url")
        self.networkapi_username = options.get("networkapi_username")
        self.networkapi_password = options.get("networkapi_password")

        #db
        self.db_host = options.get("db_host")
        self.db_user = options.get("db_user")
        self.db_password = options.get("db_password")
        self.db_database = DB_DATABASE
        self.db_connection = None
        self.api = options.get("api")
        self.table_expunging_ips = PrettyTable(["IP", "EQUIPAMENTO", "VLAN"])
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
        results = []
        network_api = NetworkApi(url=self.networkapi_url, username=self.networkapi_username, password=self.networkapi_password)
        for (private_ip_address, state, removed) in cursor:
            colums = (private_ip_address, state, removed)
            results.append(GloboNetworkIp(ip=private_ip_address, state=state, removed=removed, network_api=network_api))

        cursor.close()
        self.close_connection()

        return results


    def notify_email(self):
        self._email_body.append(self.table_expunging_ips.get_html_string())
        body = "<br/>".join(self._email_body)
        my_email = MyEmail(to=self.email_to,
                           from_=self.email_from,
                           subject=self._email_subject,
                           body=body)
        my_email.send()


    def run(self):
        globo_network_ips = self.get_expunging_ips()

        for globo_network_ip in globo_network_ips:
            column = ("%s:%s" % (globo_network_ip.ip["address"],globo_network_ip.ip["id"]),
                      "%s:%s" % (globo_network_ip.equipamento["name"],globo_network_ip.equipamento["id"]),
                      globo_network_ip.equipamento["vlan"])
            self.table_expunging_ips.add_row(column)

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
               "region": args.region,
               "networkapi_url": networkapi_url,
               "networkapi_username": networkapi_username,
               "networkapi_password": networkapi_password,}

    ip_cleaner = GloboNetworkIpCleaner(options=options)
    ip_cleaner.run()