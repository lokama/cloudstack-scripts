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




# projectid="0179062b-6b56-4695-8f0e-3b56b1c9399c"
# zoneid="e170a3c8-755f-448d-a967-b936533ccfc6"
# templateid="8478ea07-0e90-4017-bca5-453f1c1047c4"
# hypervisor="XenServer"
# serviceofferingid="0746a710-d0e3-4269-9e02-7ecf8b941e5c"
# iptonetworklist_networkid="f2bea78c-90a1-4b93-aa29-eb5597ab82d4"

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
    parser.add_argument('--use_large_userdata', type=bool, default=False,
                        help='Should I use large_userdata (27kb) to deploy a new vm? Default to false.')
    args = parser.parse_args()

    api = get_api(args=args)
    userdata_small = b'MARKER' + b'%s'%(os.urandom(2*1024))
    userdata_small = base64.b64encode(userdata_small)

    userdata_large = b'MARKER' + b'%s'%(os.urandom(20*1024))
    userdata_large = base64.b64encode(userdata_large)

    #userdata
    use_large_userdata = args.use_large_userdata
    user_data = userdata_small
    if use_large_userdata:
        user_data = userdata_large

    #deploy vm
    vm_name = "test-vm-userdata-" + timestamp
    vm = VirtualMachine(api=api,
                        display_name=vm_name,
                        name=vm_name,
                        user_data=user_data)
    result = vm.deploy()
    print result