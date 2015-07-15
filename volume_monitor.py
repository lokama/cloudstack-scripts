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


class VolumeMonitor(object):

    def __init__(self, options={}):

        self.db_host = options.get("db_host")
        self.db_user = options.get("db_user")
        self.db_password = options.get("db_password")
        self.db_database = DB_DATABASE
        self.db_connection = None
        self.api = options.get("api")
        self.table_all_volumes = PrettyTable(["ID", "ACCOUNT_ID", "NAME", "UUID", "PATH", "INSTANCE_ID", "REMOVED", "CREATED", "STATE"])
        self.table_absent_volumes = PrettyTable(["ID", "ACCOUNT_ID", "NAME", "UUID", "PATH", "INSTANCE_ID", "REMOVED", "CREATED", "STATE"])
        self.list_ids_to_update = [] #list of ids with wrong values
        self.project_account_id = None
        self.project_accounts_ids = {}
        self._is_zumbi_volume_found = False
        self._region = options.get("region", "")
        self._list_vdis = options.get("list_vdis", "")

        #email
        self.send_email = options.get("send_mail", False)
        self.email_to = options.get("email_to", "")
        self.email_from = options.get("email_from", "")
        self._email_body = []
        self._email_subject = options.get("email_subject", "[CLOUDSTACK VOLUME MONITOR %s] - zumbi volume found!" % self._region)

    def get_volume(self, id=None):
        if not id:
            return {}

        result = self.api.listVolumes({
            'listall':  'true',
            'id':  id
        })
        return result


    def open_connection(self):
        self.db_connection = mysql.connector.connect(user=self.db_user, password=self.db_password,
                                       host=self.db_host,
                                       database=self.db_database)

    def close_connection(self):
        try:
            self.db_connection.close()
        except:
            pass


    def get_computed_volumes_query(self, account_id=None):

        query = ("select v.id, v.account_id, v.name, v.uuid, v.path, v.instance_id, v.removed, v.created, v.state "
        "from cloud.volumes as v "
        "where v.account_id = %s "
        "and (v.path is not null or v.state in ('Allocated')) "
        "and v.display_volume = 1 "
        "and v.removed is null order by id" % account_id)

        #print("query: %s" % query)
        return query

    def get_project_accounts(self):

        query = ("select distinct(pa.project_account_id), p.name, p.display_text "
                "from cloud.project_account as pa, cloud.projects as p "
                "where pa.project_id = p.id")

        if self.project_account_id:
            query = query + " and pa.project_account_id = %s" % self.project_account_id

        self.open_connection()
        cursor = self.db_connection.cursor()
        cursor.execute(query)

        for (project_account_id, project_name, project_display_text) in cursor:
            self.project_accounts_ids[project_account_id] = {"name": project_name, "project_display_text": project_display_text}

        cursor.close()
        self.close_connection()

    def absent_volumes_table(self):
        self.open_connection()
        try:
            for project_account_id, project_details in self.project_accounts_ids.items():
                cursor = self.db_connection.cursor(buffered=True)
                query = self.get_computed_volumes_query(account_id=project_account_id)
                cursor.execute(query)
                total_volume_absent = 0
                try:
                    for (id, account_id, name, uuid, path, instance_id, removed, created, state) in cursor:
                        colums = [id, "%s(%s)" % (account_id, project_details["name"]), name, uuid, path, instance_id, removed, created, state]
                        self.table_all_volumes.add_row(colums)

                        #check if volume exists
                        volume = self.get_volume(id=uuid)
                        if not volume:
                            #print "\t volume %s does not exist!" % uuid
                            self.table_absent_volumes.add_row(colums)
                            self.list_ids_to_update.append(id)
                            total_volume_absent += 1
                            if not self._is_zumbi_volume_found:
                                self._is_zumbi_volume_found = True

                        #print "\t volume: %s" % volume

                    base_msg = "Total volumes absent for project_account_id %s => %s" % (project_details["name"], total_volume_absent)
                    if self.send_email:
                        self._email_body.append(base_msg)
                    if total_volume_absent > 0:
                        print Colors.FAIL + base_msg + Colors.END
                    else:
                        print Colors.OK + base_msg + Colors.END
                    time.sleep(1)
                except Exception, e:
                    print "ops... %s" % e
                    print(traceback.format_exc())


                cursor.close()
        finally:
            try:
                self.close_connection()
            except Exception, e:
                print e

        if self._is_zumbi_volume_found and self.send_email:
            print "ZUMBI volumes found!!! Sending email!"
            self._email_body.append("\n")
            self.notify_email()

    def notify_email(self):
        self._email_body.append(self.table_absent_volumes.get_html_string())
        body = "<br/>".join(self._email_body)
        my_email = MyEmail(to=self.email_to,
                from_=self.email_from,
                subject=self._email_subject,
                body=body)
        my_email.send()

    def get_vdi_list(self):
        print "\n\n\n"
        print self.table_absent_volumes.get_string(fields=["PATH"])
        print "\n\n"
        print self.list_ids_to_update

    def run(self):
        self.get_project_accounts()
        self.absent_volumes_table()

        print self.table_absent_volumes
        if self._list_vdis:
            self.get_vdi_list()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Volume Monitor')
    parser.add_argument('--region', type=str, default='lab',
                        help='Choose your region based on your cloudmonkey profile. Default profile is "lab"')
    parser.add_argument('--accountid', type=str, default='',
                        help='Account id associated to the project')
    parser.add_argument('--send_email', type=bool, default=False,
                    help='Should we send email? (Default false)')
    parser.add_argument('--email_to', type=str, default='',
                help='Send email to')
    parser.add_argument('--email_from', type=str, default='',
                help='Who is sending the email?')
    parser.add_argument('--list_vdis', type=bool, default=False,
                help='List volumes VDIs? (Default false)')
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

        apikey = parser.get(args.region, 'apikey')
        api_url = parser.get(args.region, 'url')
        secretkey = parser.get(args.region, 'secretkey')
        verifysslcert = parser.getboolean(args.region, 'verifysslcert')

        db_host = parser.get(args.region, 'db_host')
        db_user = parser.get(args.region, 'db_user')
        db_password = parser.get(args.region, 'db_password')

    else:
        sys.exit("Invalid region: '%s'" % args.region)

    project_account_id = args.accountid
    send_email = args.send_email
    email_to = ""
    email_from = ""
    if send_email:
        email_to = args.email_to
        email_from = args.email_from
        if not email_from:
            print "You did not specify the email_from option"
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
                "list_vdis": args.list_vdis}
    volume_monitor = VolumeMonitor(options=options)
    if project_account_id:
        volume_monitor.project_account_id = project_account_id
    volume_monitor.run()