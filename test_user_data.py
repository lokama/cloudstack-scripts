import base64
import logging
from prettytable import PrettyTable
from ACSConn import CloudStack
from colors import Colors
import argparse
import os
import sys
import datetime
import time
from ConfigParser import SafeConfigParser

LOG = logging.getLogger(__name__)


projectid="e3d3b266-f5f3-4b1c-a663-1944f53f113f"
zoneid="3858ea76-d143-498a-8cf7-975324a60b14"
templateid="fc28b5f8-ca07-4a24-85d4-c4fa158668a3"
hypervisor="XenServer"
serviceofferingid="84353183-e347-4443-9e5f-9ab078e4ba03"
iptonetworklist_networkid="5be43741-63ca-4c31-aeb2-68262bc5695b"

class VirtualMachine(object):

    def __init__(self, api=None, display_name=None, name=None, user_data=''):
        self.api = api
        self.display_name = display_name
        self.name = name
        self.user_data = user_data

    def deploy(self):
        result = self.api.deployVirtualMachine('POST', {
            'displayname': self.display_name,
            'hypervisor': hypervisor,
            'serviceofferingid': serviceofferingid,
            'projectid':  projectid,
            'zoneid': zoneid,
            'templateid': templateid,
            'iptonetworklist[0].networkid': iptonetworklist_networkid,
            'name': self.name,
            'userdata': self.user_data
        })
        return result

def get_api(args=None):
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
        verifysslcert = parser.getboolean(args.region, 'verifysslcert')
    else:
        sys.exit("Invalid region: '%s'" % args.region)
    api = CloudStack(api_url, apikey, secretkey, verifysslcert)
    return api


if __name__ == "__main__":

    ts = time.time()
    timestamp = datetime.datetime.fromtimestamp(ts).strftime('%d%m%Y-%H%M%S')

    parser = argparse.ArgumentParser(description='Check Cloudstack status')
    parser.add_argument('--region', type=str, default='lab',
                        help='Choose your region based on your cloudmonkey profile. Default profile is "lab"')
    args = parser.parse_args()

    api = get_api(args=args)
    userdata_2k = b'MARKER' + b'%s'%(os.urandom(2*1024))
    userdata_2k = base64.b64encode(userdata_2k)

    #print "userdata_2k: %s" % userdata_2k

    userdata_large = b'MARKER' + b'%s'%(os.urandom(20*1024))
    userdata_large = base64.b64encode(userdata_large)

    #print "userdata_33k: %s" % userdata_large

    #deploy vm
    vm_name = "test-vm-userdata-" + timestamp
    vm = VirtualMachine(api=api,
                        display_name=vm_name,
                        name=vm_name,
                        user_data=userdata_2k)
    result = vm.deploy()
    print result