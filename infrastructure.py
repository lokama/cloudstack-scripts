#!/usr/bin/env python
# TODO

import argparse
import os
import sys
import uuid
from ConfigParser import SafeConfigParser
from ACSConn import CloudStack
from prettytable import PrettyTable

parser = argparse.ArgumentParser(description='Check Cloudstack status')
parser.add_argument('--vm', action="store_true", help='List virtualmachine with ordering option (--order)')
parser.add_argument('--project', action="store_true", help='Resource usage by projects, ordered by project name')
parser.add_argument('--cluster', action="store_true", help='Cluster capacity, ordered by used resources')
parser.add_argument('--vr', action="store_true", help='State and version of Virtual Routers')
parser.add_argument('--ssvm', action="store_true", help='State of system vms')
parser.add_argument('--lb', type=str, help="List LoadBalancer by project or account")
parser.add_argument('--userdata', action="store_true", help='Show userdata length for each VM')
parser.add_argument('--reset_userdata', type=str, help='Reset userdata by project id or vm id')
parser.add_argument('--capacity', action="store_true", help='Capacity by zone and type, ordered by used resources')
parser.add_argument('--network', action="store_true", help='List networks all networks')
parser.add_argument('--region', type=str, default='lab',
                    help='Choose your region based on your cloudmonkey profile. Default profile is "lab"')
parser.add_argument('--order', type=str,
                    help='Argument with --vm to order by Name, State, Hostname, Service Offering or Zone. Default is Project')
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
else:
    sys.exit("Invalid region: '%s'" % args.region)
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


class Colors(object):
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Configurations(object):
    'Global Settings from ACS'

    def get(self, name):
        result = api.listConfigurations({
            'name': name
        })
        return result['configuration'][0]


class Accounts(object):
    'Accounts'

    def old_list_all(self, param):
        result = api.listAccounts({
            'listall':  'true'
        })
        acc_ids = []
        for acc_id in result['account']:
            acc_ids.append(acc_id[param])
        return acc_ids

    def list_all(self):
        return api.listAccounts({
            'listall':  'true'
        })


class Projects(object):
    'Projects'

    def get(self, param):
        result = api.listProjects({
            'listall':  'true',
            'state':    'Active'
        })
        if 'project' in result:
            p_ids = []
            for p_id in result['project']:
                p_ids.append(p_id[param])
            return p_ids
        else:
            sys.exit("There is no projects on this region!")

    def detail(self, **kwargs):
        return api.listProjects(kwargs)

    def list_all(self):
        return api.listProjects({
            'listall':  'true',
            'state':    'Active'
        })


class VMs(object):
    'VMs'

    def list(self, project_id):
        result = api.listVirtualMachines({
            'listall':      'true',
            'projectid':    project_id
        })
        return result


class UserData(object):
    'Userdata actions'

    def get(self, vm_id):
        result = api.getVirtualMachineUserData({
            'virtualmachineid': vm_id
        })
        return result

    def reset(self, vm_id):
        result = api.updateVirtualMachine({
            'userdata':     'ZWNobwo=',
            'id':           vm_id
        })
        return result


class Networks(object):
    'Networks by account and project'

    def get(self, project_id):
        return api.listNetworks({
            'projectid':    project_id,
            'listall':      'true'
        })

    def get_detail(self, **kwargs):
        result = api.listNetworks(kwargs)
        if result:
            # return result['network'][0]
            return result['network']


def percentage(part, whole):
    return 100 * int(part)/int(whole)


def show_projects_usage():
    pjt = Projects()
    result = pjt.list_all()
    t = PrettyTable(['Project', 'Account', 'CPU', 'MEM (GB)', 'Pri Stg (GB)', 'Sec Stg (GB)',
                    'Templates', 'VM', 'Volume'])
    t.align['Project'] = 'l'
    for res in result['project']:
        if (
            int(res['cputotal']) > int(res['cpulimit']) or
            int(res['memorytotal']) > int(res['memorylimit']) or
            int(res['primarystoragetotal']) > int(res['primarystoragelimit']) or
            int(res['secondarystoragetotal']) > int(res['secondarystoragelimit']) or
            int(res['templatetotal']) > int(res['templatelimit']) or
            int(res['vmtotal']) > int(res['vmlimit']) or
            int(res['volumetotal']) > int(res['volumelimit'])
        ):
            c_init = Colors.FAIL
        else:
            c_init = ''
        t.add_row([c_init + res['name'], res['account'],
                  "%s/%s (%s" % (res['cputotal'], res['cpulimit'], percentage((res['cputotal']),
                                 (res['cpulimit']))) + "%)",
                  "%s/%s (%s" % (int(res['memorytotal'])/1024, int(res['memorylimit'])/1024,
                                 percentage(int(res['memorytotal'])/1024, int(res['memorylimit'])/1024)) + "%)",
                  "%s/%s (%s" % (res['primarystoragetotal'], res['primarystoragelimit'],
                                 percentage((res['primarystoragetotal']), (res['primarystoragelimit']))) + "%)",
                  "%s/%s (%s" % (res['secondarystoragetotal'], res['secondarystoragelimit'],
                                 percentage((res['secondarystoragetotal']), (res['secondarystoragelimit']))) + "%)",
                  "%s/%s (%s" % (res['templatetotal'], res['templatelimit'], percentage((res['templatetotal']),
                                 (res['templatelimit']))) + "%)",
                  "%s/%s (%s" % (res['vmtotal'], res['vmlimit'], percentage((res['vmtotal']), (res['vmlimit']))) + "%)",
                  "%s/%s (%s" % (res['volumetotal'], res['volumelimit'], percentage((res['volumetotal']),
                                 (res['volumelimit']))) + "%)" + Colors.ENDC])
    return t.get_string(sortby="Project")


def show_clusters_usage():
    result = api.listClusters({
        'showcapacities':   'true',
        'allocationstate':  'Enabled'
    })
    t = PrettyTable(['Zone', 'Cluster', 'Pod', 'Type', 'Used (%)', 'To Threshold', 'Free (GB/unit)'])

    conf = Configurations()

    for res in result['cluster']:
        for r in res['capacity']:
            if (r['type'] == 0):
                # memory
                threshold = float(conf.get('cluster.memory.allocated.capacity.disablethreshold')['value'])
            elif (r['type'] == 1):
                # CPU
                threshold = float(conf.get('cluster.cpu.allocated.capacity.disablethreshold')['value'])
            elif (r['type'] == 2):
                # Storage
                threshold = float(conf.get('pool.storage.capacity.disablethreshold')['value'])
            elif (r['type'] == 3):
                # Allocated Storage
                threshold = float(conf.get('pool.storage.allocated.capacity.disablethreshold')['value'])
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


def show_vrs():
    # show project
    result = api.listRouters({
        'listall':  'true',
    })
    t = PrettyTable(['Name', 'State', 'Zone', 'Host', 'Version', 'Network Domain', 'Networkname', 'Link Local IP',
                    'Guest IP Addr', 'Network ID'])

    if 'router' in result:
        for rtr in result['router']:
            if 'hostname' not in rtr:
                rtr['hostname'] = 'N/A'
            if 'linklocalip' not in rtr:
                rtr['linklocalip'] = 'N/A'
            if 'networkdomain' not in rtr:
                rtr['networkdomain'] = 'N/A'
            for device in rtr['nic']:
                if device['traffictype'] == 'Guest':
                    if 'networkid' in device:
                        ntw_id = device['networkid']
                    if 'networkname' in device:
                        ntw_name = device['networkname']
                    if 'ip6address' in device:
                        ip_addr = device['ip6address']
                    if 'ipaddress' in device:
                        if not device['ipaddress'].startswith('169'):
                            ip_addr = device['ipaddress']

            t.add_row([rtr['name'], rtr['state'], rtr['zonename'], rtr['hostname'], rtr['version'],
                      rtr['networkdomain'], ntw_name, rtr['linklocalip'], ip_addr, ntw_id])
        return t.get_string(sortby="Version", reversesort=True)
    else:
        sys.exit("There is no VR's in this region")


def show_loadbalancers():
    proj = Projects()
    acct = Accounts()
    # by project or account
    if args.lb == 'project':
        all_lb = proj.get('id')
        param_type = 'projectid'
        lst_type = 'project'
    elif args.lb == 'account':
        all_lb = acct.old_list_all('name')
        param_type = 'account'
        lst_type = 'account'
    else:
        sys.exit("Invalid lb option\n Use: --lb project or --lb account")

    t = PrettyTable([lst_type.capitalize(), 'State', 'Name', 'PublicIP', 'CIDR', 'Network Name', 'Network Domain',
                    'Additional Networks'])

    for project_id in all_lb:
        result = api.listLoadBalancerRules({
            'listall':      'true',
            param_type:     project_id
        })
        # if project has LB
        if result:
            ntw = Networks()
            # Get details from network
            for lb in result['loadbalancerrule']:
                network_details = ntw.get_detail(id=lb['networkid'], **{param_type: project_id})[0]
                # get details from additional network(s) in LB
                additional_network = []
                if lb['additionalnetworkids']:
                    for adt_network in lb['additionalnetworkids']:
                        print ntw.get_detail(id=adt_network, **{param_type: project_id})[0]['name']
                        additional_network.append(str(ntw.get_detail(id=adt_network, **{param_type: project_id})[0]['name']))
                t.add_row([lb[lst_type], lb['state'], lb['name'], lb['publicip'], network_details['cidr'],
                          network_details['name'], network_details['networkdomain'], additional_network])
    return t.get_string(sortby=lst_type.capitalize())


def show_ssvms():
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


def show_capacities():
    result = api.listCapacity({})
    t = PrettyTable(['Type', 'Zone', 'Used (%)'])
    t.align['Type'] = 'l'
    for rsc_type in result['capacity']:
        t.add_row([capacity_type[rsc_type['type']], rsc_type['zonename'], float(rsc_type['percentused'])])
    return t.get_string(sortby="Used (%)", reversesort=True)


def show_userdata():
    proj = Projects()
    vm_data = UserData()
    vms = VMs()
    # list by project
    t = PrettyTable(['Project', 'Vm Name', 'VM ID', 'Length'])
    for project in proj.get('id'):
        project_name = proj.detail(id=project, listall='true')['project'][0]['name']
        print "Getting userdata from project '%s' (id:%s)" % (project_name, project)
        result = vms.list(project)
        if 'virtualmachine' in result:
            for vm in result['virtualmachine']:
                userdata = vm_data.get(vm['id'])['virtualmachineuserdata']
                if 'userdata' in userdata:
                    t.add_row([project_name, vm['name'], vm['id'], len(userdata['userdata'])])
    return t.get_string(sortby="Length", reversesort=True)


def show_vms():
    proj = Projects()
    vms = VMs()
    t = PrettyTable(['Project', 'Name', 'ID', 'State', 'Hostname', 'Service Offering', 'Zone'])
    for project in proj.get('id'):
        project_name = proj.detail(id=project, listall='true')['project'][0]['name']
        result = vms.list(project)
        if 'virtualmachine' in result:
            for vm in result['virtualmachine']:
                if not 'hostname' in vm:
                    vm['hostname'] = '-'
                t.add_row([project_name, vm['name'], vm['id'], vm['state'], vm['hostname'],
                          vm['serviceofferingname'], vm['zonename']])
    if args.order:
        return t.get_string(sortby=args.order)
    else:
        return t.get_string(sortby="Project")


def show_networks():
    pjts = Projects().list_all()
    ntws = Networks()
    # Show all accounts and projects
    t = PrettyTable(['Account', 'Project', 'Name', 'Status', 'ID', 'Network Domain', 'CIDR', 'Zone'])

    # public networks
    for netact in ntws.get_detail(**{'listall': 'true'}):
        if 'account' not in netact:
            netact['account'] = 'N/A'
        if 'ip6cidr' in netact:
            cidr = netact['ip6cidr']
        elif 'cidr' in netact:
            cidr = netact['cidr']
        if 'networkdomain' not in netact:
            netact['networkdomain'] = 'N/A'
        project = 'N/A'

        if netact['account'] == 'N/A':
            c_init = Colors.FAIL
        elif 'SANITY' in netact['name'].upper():
            c_init = Colors.WARNING
        else:
            c_init = ''

        t.add_row([c_init + netact['account'], project, netact['name'], netact['state'], netact['id'],
                  netact['networkdomain'], cidr, netact['zonename'] + Colors.ENDC])

    if 'project' in pjts:
        for actpj in pjts['project']:
            result = ntws.get(actpj['id'])
            if len(result) < 1:
                continue
            for n in result['network']:
                if 'account' in n:
                    account = n['account']
                else:
                    account = 'N/A'
                if 'subdomainaccess' not in n:
                    if 'cidr' in n:
                        cidr = n['cidr']
                    elif 'ip6cidr' in n:
                        cidr = n['ip6cidr']
                    else:
                        cidr = 'N/A'
                    t.add_row([account, actpj['name'], n['name'], n['state'], n['id'],
                              n['networkdomain'], cidr, n['zonename']])
    return t.get_string(sortby='Project')


def reset_userdata(project_id):
    vm_data = UserData()
    proj = Projects()
    vms = VMs()
    if 'project' in proj.detail(id=project_id, listall='true'):
        project_name = proj.detail(id=project_id, listall='true')['project'][0]['name']
    else:
        sys.exit("There is no project with id: '%s'" % project_id)

    shall = raw_input("Remove userdata from _all_ VM's on project '%s' (y/N) " % project_name).lower() == 'y'
    if shall:
        result = vms.list(project_id)
        if result:
            for vm in result['virtualmachine']:
                usrdata = vm_data.get(vmid=vm['id'])['virtualmachineuserdata']
                if 'userdata' in usrdata:
                    print "Reseting userdata from vm: %s" % (vm['name'])
                    vm_data.reset(vm['id'])


if args.project:
    print show_projects_usage()
elif args.cluster:
    print show_clusters_usage()
elif args.vr:
    print show_vrs()
elif args.ssvm:
    print show_ssvms()
elif args.capacity:
    print show_capacities()
elif args.lb:
    print show_loadbalancers()
elif args.userdata:
    print show_userdata()
elif args.vm:
    print show_vms()
elif args.network:
    print show_networks()
elif args.reset_userdata:
    try:
        uuid.UUID(args.reset_userdata, version=4)
        reset_userdata(args.reset_userdata)
    except ValueError:
        sys.exit("The id provided does not look like an uuid")
