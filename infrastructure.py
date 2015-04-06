#!/usr/bin/env python
# TODO
# list network by account

import argparse
import os
import sys
from ConfigParser import SafeConfigParser
from ACSConn import CloudStack
from prettytable import PrettyTable

parser = argparse.ArgumentParser(description='Check Cloudstack status')
parser.add_argument('--project', action="store_true", help='Resource usage by projects, ordered by project name')
parser.add_argument('--cluster', action="store_true", help='Cluster capacity, ordered by used resources')
parser.add_argument('--vr', action="store_true", help='State and version of Virtual Routers')
parser.add_argument('--ssvm', action="store_true", help='State of system vms')
parser.add_argument('--lb', type=str, help="List LoadBalancer by project or account")
parser.add_argument('--userdata', action="store_true", help='Show userdata length for each VM')
parser.add_argument('--capacity', action="store_true", help='Capacity by zone and type, ordered by used resources')
parser.add_argument('--region', type=str, default='lab', help='Choose your region based on your cloudmonkey profile. Default profile is "lab"')
args = parser.parse_args()


# import keys from cloudmonkey config
parser = SafeConfigParser()
parser.read(os.path.expanduser('~/.cloudmonkey/config'))
if parser.has_section(args.region):
    if not parser.has_option(args.region, 'url'):
        print "There is no url option in '%s' section" % args.region
        sys.exit(1)
    if not parser.has_option(args.region, 'apikey'):
        print "There is no 'apikey' option in '%s' section" % args.region
        sys.exit(1)
    if not parser.has_option(args.region, 'secretkey'):
        print "There is no 'secretkey' option in '%s' section" % args.region
        sys.exit(1)

    apikey = parser.get(args.region, 'apikey')
    api_url = parser.get(args.region, 'url')
    secretkey = parser.get(args.region, 'secretkey')
else:
    print "Invalid region: '%s'" % args.region
    sys.exit(1)

api = CloudStack(api_url, apikey, secretkey)

capacity_type = {
    0:  'Memory',
    1:  'CPU',
    2:  'Storage',
    3:  'Stg Allocated',
    4:  'Public IP',
    5:  'Private IP',
    6:  'Secondary Stg',
    7:  'Vlan',
    8:  'Direct Attc Pub IP',
    9:  'Local Storage',
    19: 'GPU'
}


def get_configuration(name):
    result = api.listConfigurations({
        'name': name
    })
    return result['configuration']


def get_accounts(param):
    result = api.listAccounts({
        'listall':  'true'
    })
    acc_ids = []
    for acc_id in result['account']:
        acc_ids.append(acc_id[param])
    return acc_ids


def get_projects(param):
    result = api.listProjects({
        'listall':  'true',
        'state':    'Active'
    })
    p_ids = []
    for p_id in result['project']:
        p_ids.append(p_id[param])
    return p_ids


def get_project_detail(**kwargs):
    return api.listProjects(kwargs)


def get_network_detail(**kwargs):
    result = api.listNetworks(kwargs)
    if result:
        return result['network'][0]


def get_userdata(vmid):
    result = api.getVirtualMachineUserData({
        'virtualmachineid': vmid
    })
    return result

def percentage(part, whole):
  return 100 * int(part)/int(whole)

def list_projects():
    result = api.listProjects({
        'listall':  'true',
        'state':    'Active'
    })
    t = PrettyTable(['Project', 'Account', 'CPU', 'MEM (GB)', 'Pri Stg (GB)', 'Sec Stg (GB)',
                    'Templates', 'VM', 'Volume'])
    t.align['Project'] = 'l'
    for res in result['project']:
        t.add_row([res['name'], res['account'],
                  "%s/%s (%s" % (res['cputotal'], res['cpulimit'], percentage((res['cputotal']), (res['cpulimit']))) + "%)",
                  "%s/%s (%s" % (int(res['memorytotal'])/1024, int(res['memorylimit'])/1024, percentage(int(res['memorytotal'])/1024, int(res['memorylimit'])/1024)) + "%)",
                  "%s/%s (%s" % (res['primarystoragetotal'], res['primarystoragelimit'], percentage((res['primarystoragetotal']), (res['primarystoragelimit']))) + "%)",
                  "%s/%s (%s" % (res['secondarystoragetotal'], res['secondarystoragelimit'], percentage((res['secondarystoragetotal']), (res['secondarystoragelimit']))) + "%)",
                  "%s/%s (%s" % (res['templatetotal'], res['templatelimit'], percentage((res['templatetotal']), (res['templatelimit']))) + "%)",
                  "%s/%s (%s" % (res['vmtotal'], res['vmlimit'], percentage((res['vmtotal']), (res['vmlimit']))) + "%)",
                  "%s/%s (%s" % (res['volumetotal'], res['volumelimit'], percentage((res['volumetotal']), (res['volumelimit']))) + "%)"])
    return t.get_string(sortby="Project")


def list_clusters():
    result = api.listClusters({
        'showcapacities':   'true',
        'allocationstate':  'Enabled'
    })
    t = PrettyTable(['Zone', 'Cluster', 'Pod', 'Type', 'Used (%)', 'To Threshold', 'Free (GB/unit)'])

    for res in result['cluster']:
        for r in res['capacity']:
            if (r['type'] == 0):
                # memory
                threshold = float(get_configuration('cluster.memory.allocated.capacity.disablethreshold')[0]['value'])
            elif (r['type'] == 1):
                # CPU
                threshold = float(get_configuration('cluster.cpu.allocated.capacity.disablethreshold')[0]['value'])
            elif (r['type'] == 2):
                # Storage
                threshold = float(get_configuration('pool.storage.capacity.disablethreshold')[0]['value'])
            elif (r['type'] == 3):
                # Allocated Storage
                threshold = float(get_configuration('pool.storage.allocated.capacity.disablethreshold')[0]['value'])
            else:
                threshold = 1

            # if the resource is not unit, convert to GB
            if (r['type'] in [0, 2, 3, 6, 9]):
                convert_unit = 1024*1024*1024
            else:
                convert_unit = 1

            free_until_hit_threshold = int(((r['capacitytotal'] * threshold) - r['capacityused'])/convert_unit)
            total_free_resource = (r['capacitytotal'] - r['capacityused'])/convert_unit

            t.add_row([res['zonename'], res['name'], res['podname'], capacity_type[r['type']], float(r['percentused']),
                      free_until_hit_threshold, total_free_resource])

    return t.get_string(sortby="Used (%)", reversesort=True)


def list_vrs():
    result = api.listRouters({
        'listall':  'true',
    })
    t = PrettyTable(['Name', 'State', 'Zone', 'Host', 'Version', 'Network Domain', 'Networkname', 'Link Local IP',
                    'Guest IP Addr'])
    for rtr in result['router']:
        for device in rtr['nic']:
            if 'networkname' in device:
                ntw_name = device['networkname']
            if 'ip6address' in device:
                ip_addr = device['ip6address']
            elif device.get('ipaddress'):
                if not device['ipaddress'].startswith('169'):
                    ip_addr = device['ipaddress']

        t.add_row([rtr.get('name'), rtr.get('state'), rtr.get('zonename'), rtr.get('hostname'), rtr.get('version'), rtr.get('networkdomain'),
                  ntw_name, rtr.get('linklocalip'), ip_addr])
    return t.get_string(sortby="Version", reversesort=True)


def list_ssvms():
    result = api.listSystemVms({})
    t = PrettyTable(['Name', 'Version', 'State', 'Agent', 'Type', 'Zone', 'Host'])
    for ssvm in result['systemvm']:
        agent_status = api.listHosts({
            'name':     ssvm['name']
        })
        # if ssvm is not in running state, the xen host is empty.
        if not 'hostname' in ssvm:
            ssvm['hostname'] = '-'
        t.add_row([ssvm['name'], agent_status['host'][0]['version'], ssvm['state'], agent_status['host'][0]['state'],
                  ssvm['systemvmtype'], ssvm['zonename'], ssvm['hostname']])
    return t.get_string(sortby="Zone")


def list_capacities():
    result = api.listCapacity({})
    t = PrettyTable(['Type', 'Zone', 'Used (%)'])
    t.align['Type'] = 'l'
    for rsc_type in result['capacity']:
        t.add_row([capacity_type[rsc_type['type']], rsc_type['zonename'], float(rsc_type['percentused'])])
    return t.get_string(sortby="Used (%)", reversesort=True)


def list_loadbalancers():
    # by project or account
    if args.lb == 'project':
        all_lb = get_projects('id')
        param_type = 'projectid'
        lst_type = 'project'
    elif args.lb == 'account':
        all_lb = get_accounts('name')
        param_type = 'account'
        lst_type = 'account'
    else:
        print "Invalid lb option\n Use: --lb project or --lb account"
        sys.exit(1)

    t = PrettyTable([lst_type.capitalize(), 'State', 'Name', 'PublicIP', 'CIDR', 'Network Name', 'Network Domain',
                    'Additional Networks'])

    for project_id in all_lb:
        result = api.listLoadBalancerRules({
            'listall':      'true',
            param_type:     project_id
        })
        # if project has LB
        if result:
            # Get details from network
            for lb in result['loadbalancerrule']:
                network_details = get_network_detail(id=lb['networkid'], **{param_type: project_id})
                # get details from additional network(s) in LB
                additional_network = []
                if lb['additionalnetworkids']:
                    for adt_network in lb['additionalnetworkids']:
                        additional_network.append(get_network_detail(id=adt_network, **{param_type: project_id})['name'])
                t.add_row([lb[lst_type], lb['state'], lb['name'], lb['publicip'], network_details['cidr'],
                          network_details['name'], network_details['networkdomain'], additional_network])
    return t.get_string(sortby=lst_type.capitalize())


def list_userdata():
    t = PrettyTable(['Project', 'Vm Name', 'VM ID', 'Length'])
    for project in get_projects('id'):
        project_name = get_project_detail(id=project, listall='true')['project'][0]['name']
        result = api.listVirtualMachines({
            'listall':      'true',
            'projectid':    project
        })
        if 'virtualmachine' in result:
            for vm in result['virtualmachine']:
                userdata = get_userdata(vmid=vm['id'])['virtualmachineuserdata']
                if 'userdata' in userdata:
                    t.add_row([project_name, vm['name'], vm['id'], len(userdata['userdata'])])
    return t.get_string(sortby="Length", reversesort=True)

if args.project:
    print list_projects()
elif args.cluster:
    print list_clusters()
elif args.vr:
    print "List VR's in 'Running' state!"
    print list_vrs()
elif args.ssvm:
    print list_ssvms()
elif args.capacity:
    print list_capacities()
elif args.lb:
    print list_loadbalancers()
elif args.userdata:
    print list_userdata()
