## Overview

Helpful cloudstack script(s) to show what's going on with your resources on cloudstack.


## Features

### Resource
* Resource usage by project
* Resource usage/capacity by hypervisor cluster
* Resource usage/capacitu by zone

### System vm's
* Details about every virtual router
* State of system vms

### Userdata
* List virtual machines are using userdata
* Reset userdata per project id

### Load Balancer
* List load balancer by project or account

### Virtual Machines
* List virtual machines and its details (hypervisor, host, project)

## Requirements

* [cloudmonkey config file (cloudmonkey >5.2.0): ~/.cloudstack/config](https://cwiki.apache.org/confluence/display/CLOUDSTACK/CloudStack+cloudmonkey+CLI#CloudStackcloudmonkeyCLI-Managementserverprofiles)
* Satisfy all python requirements in the requirements.txt file

\

	$ pip install -r requirements.txt

## Executing script

```
$ ./infrastructure.py -h
usage: infrastructure.py [-h] [--vm] [--project] [--cluster] [--vr] [--ssvm]
                         [--lb LB] [--userdata] [--capacity] [--region REGION]
                         [--order ORDER]

Check Cloudstack status

optional arguments:
  -h, --help       show this help message and exit
  --vm             List virtualmachine with ordering option (--order)
  --project        Resource usage by projects, ordered by project name
  --cluster        Cluster capacity, ordered by used resources
  --vr             State and version of Virtual Routers
  --ssvm           State of system vms
  --lb LB          List LoadBalancer by project or account
  --userdata       Show userdata length for each VM
  --capacity       Capacity by zone and type, ordered by used resources
  --region REGION  Choose your region based on your cloudmonkey profile.
                   Default profile is "lab"
  --order ORDER    Argument with --vm to order by Name, State, Hostname,
                   Service Offering or Zone. Default is Project
```

