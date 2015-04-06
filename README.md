## Overview

Helpful cloudstack script to show what's going on with your cloudsatck.


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
* List virtual machines and its details (hypervisor host, project)

## Requirements

* cloudmonkey config file (cloudmonkey >5.2.0): ~/.cloudstack/config
* Satisfy all python requirements in the requirements.txt file

\

	$ pip install -r requirements.txt

