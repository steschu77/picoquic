# Debian Virtual Machines for Network Simulation #

## Motivation ##

For simulating a network between two QUIC endpoints a Virtual Machine based approach can be used. This can help testing congestion control algorithms and packet loss situations closer to real world scenarios.

## Setup ##

The proposed method uses two Debian Linux VMs that are connected via an NAT network. In addition they have a second network device for communication via SSH with the host system, such that there is no direct UI based interaction with the VMs necessary.

For network simulation, Linux built-in tools like iptables and tc are used. This is controlled by a set of scripts called "comcast".

With properly setup SSH access this system can be automated as described below.

## Installation ##

Prepare Virtual Box

- Create a "NAT Network"
  - "File" - "Settings" - "Network" - "Add"
- Allow SSH Port Forwarding for "NAT Network"
  - "Modify" - "Network" - "Adapter 1" - "Extended" - "Port Forwarding"
  - Name: "SSH-xx", Protocol: "TCP", Host IP: "127.0.2.xx", Host Port: 22, Guest IP: "10.0.2.xx", Guest Port: "22"

Create the VM

A minimal Debian 10 system with all tools and libraries required to build picoquic requires 2 GB. Additional 400 MB are required for the "comcast" network degradation script and its dependencies.

When creating the harddisk for the VM additional space for temporary files and log files should be reserved.

- Enable "NAT Network" device for each VM
  - "Modify" - "Network"
  - enable Adapter 1 and choose "NAT Network"

Choose a minimal Debian Image for installation. The base system and the SSH server are sufficient to install.

After the base system has been installed, login to the VM and run the following commands as root:

```
apt install sudo pkg-config git clang binutils cmake libssl-dev
/usr/sbin/adduser <username> sudo
```

Once that is done, the VM can be accessed from the host system via

```
ssh <username>@127.0.2.<1,2>
```

At this point you may wish to setup key-based authentication already. The Automation section below describes how that is done.

Finally the NAT network between the VMs needs to be set up.

## Automation ##
