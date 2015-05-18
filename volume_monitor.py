import mysql.connector
import logging
from prettytable import PrettyTable
from ACSConn import CloudStack
from colors import Colors
import argparse
import os
import sys
import time
from ConfigParser import SafeConfigParser

LOG = logging.getLogger(__name__)

DB_DATABASE = "cloud"


# class Colors(object):
#     OK = '\033[92m'
#     WARNING = '\033[93m'
#     FAIL = '\033[91m'
#     END = '\033[0m'
#     BOLD = '\033[1m'
#     UNDERLINE = '\033[4m'


class VolumeMonitor(object):

    def __init__(self, api=None, db_host=None, db_user=None, db_password=None):
        self.db_host = db_host
        self.db_user = db_user
        self.db_password = db_password
        self.db_database = DB_DATABASE
        self.db_connection = None
        self.api = api
        self.table_all_volumes = PrettyTable(["ID", "ACCOUNT_ID", "NAME", "UUID", "PATH", "POOL_ID", "TEMPLATE_ID", "INSTANCE_ID", "REMOVED"])
        self.table_absent_volumes = PrettyTable(["ID", "ACCOUNT_ID", "NAME", "UUID", "PATH", "POOL_ID", "TEMPLATE_ID", "INSTANCE_ID", "REMOVED"])
        self.project_account_id = None
        self.project_accounts_ids = {}

    def get_volume(self, id=None):
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


    def get_query(self, account_id=None):

        query = ("select v.id, v.account_id, v.name, v.uuid, v.path, v.pool_id, v.template_id, v.instance_id, v.removed "
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

    def list_absent_volumes(self):
        cursor = self.db_connection.cursor()
        for project_account_id, project_details in self.project_accounts_ids.items():
            query = self.get_query(account_id=project_account_id)
            cursor.execute(query)
            total_volume_absent = 0
            try:
                for (id, account_id, name, uuid, path, pool_id, template_id, instance_id, removed) in cursor:
                    colums = [id, "%s(%s)" % (account_id, project_details["name"]), name, uuid, path, pool_id, template_id, instance_id, removed]
                    self.table_all_volumes.add_row(colums)

                    #check if volume exists
                    volume = self.get_volume(id=uuid)
                    if not volume:
                        #print "\t volume %s does not exist!" % uuid
                        self.table_absent_volumes.add_row(colums)
                        total_volume_absent += 1

                    #print "\t volume: %s" % volume

                if total_volume_absent > 0:
                    print Colors.FAIL + "Total volumes absent for project_account_id %s => %s" % (project_details["name"], total_volume_absent) + Colors.END
                else:
                    print "Total volumes absent for project_account_id %s => %s" % (project_details["name"], total_volume_absent)
                time.sleep(1)
            except Exception, e:
                print "ops... %s" % e

        cursor.close()

    def run(self):
        self.get_project_accounts()
        self.open_connection()
        self.list_absent_volumes()
        self.close_connection()

        print self.table_absent_volumes

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Volume Monitor')
    parser.add_argument('--region', type=str, default='lab',
                        help='Choose your region based on your cloudmonkey profile. Default profile is "lab"')
    parser.add_argument('--accountid', type=str, default='',
                        help='Account id associated to the project')
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

        apikey = parser.get(args.region, 'apikey')
        api_url = parser.get(args.region, 'url')
        secretkey = parser.get(args.region, 'secretkey')
        db_host = parser.get(args.region, 'db_host')
        db_user = parser.get(args.region, 'db_user')
        db_password = parser.get(args.region, 'db_password')
    else:
        sys.exit("Invalid region: '%s'" % args.region)

    project_account_id = args.accountid

    print "account id => %s" % project_account_id
    api = CloudStack(api_url, apikey, secretkey)
    volume_monitor = VolumeMonitor(api=api, db_host=db_host, db_user=db_user, db_password=db_password)
    if project_account_id:
        volume_monitor.project_account_id = project_account_id
    volume_monitor.run()