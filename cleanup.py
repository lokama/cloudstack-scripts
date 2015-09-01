#!/usr/bin/env python

# pip install mysql-connector-python

import re
import os
import sys
import mysql.connector
from infrastructure import Projects, LoadBalancer

acs_env = ["ACS_DB_USER", "ACS_DB_PASSWORD", "ACS_DB_HOST"]

if not set(acs_env) < set(os.environ.keys()):
    print "Please set these environment variables ACS_DB_USER, ACS_DB_PASSWORD and ACS_DB_HOST."
    sys.exit(1)

config = {
    'user': os.environ["ACS_DB_USER"],
    'password': os.environ["ACS_DB_PASSWORD"],
    'host': os.environ["ACS_DB_HOST"],
    'database': 'cloud',
    'raise_on_warnings': True,
}

cnx = mysql.connector.connect(**config)
cursor = cnx.cursor()

query = ("SELECT account_id, display_text, created \
         FROM networks \
         WHERE removed is null \
         AND traffic_type = 'Guest' \
         AND display_text like 'sanity%' \
         AND account_id in (SELECT id FROM account WHERE removed is not null)"
         )

cursor.execute(query)

for (account_id, display_text, created) in cursor:
    print account_id, display_text, created

cursor.close()
cnx.close()

def check_and_remove_lb(project_id):
    lb = LoadBalancer()
    try:
        for lbs in lb.list(projectid=project_id)['loadbalancerrule']:
            print "Destroying lb '%s' (%s)" % (lbs['name'], lbs['id'])
            lb_response = lb.delete(projectid=project_id, id=lbs['id'])
            print lb_response
    except:
        print "Unexpected error!"
        raise

proj = Projects()
project_name = proj.detail(keyword='sanity-', listall='true')
for p in project_name['project']:
    # yeah, double check for sanity name
    if re.match("^sanity-", p['name']):
        print "Project: %s id: %s" % (p['name'], p['id'])
        check_and_remove_lb(p['id'])