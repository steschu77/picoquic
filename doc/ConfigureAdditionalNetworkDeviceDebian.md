If only the first network adapter is enabled, run the following commands to enable the second one.

First check the current state of the adapters by running

```
ip a

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:2c:02:09 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s3
       valid_lft 85041sec preferred_lft 85041sec
    inet6 fe80::a00:27ff:fe2c:209/64 scope link
       valid_lft forever preferred_lft forever
3: enp0s8: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 08:00:27:a2:0c:ae brd ff:ff:ff:ff:ff:ff
```

To enable the third network device `enp0s8` edit `/etc/network/interfaces` and add the following two lines at the end of the file.

```
allow-hotplug enp0s8
iface enp0s8 inet dhcp
```

Your `/etc/network/interfaces` file should now look like this

```
source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug enp0s3
iface enp0s3 inet dhcp

allow-hotplug enp0s8
iface enp0s8 inet dhcp
```

Now run the following command to enable the network adapter. 

```
sudo /sbin/ifup enp0s8
```

Verify that the adapter has been enabled

```
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:a2:0c:ae brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.5/24 brd 10.0.2.255 scope global dynamic enp0s8
       valid_lft 170sec preferred_lft 170sec
    inet6 fe80::a00:27ff:fea2:cae/64 scope link
       valid_lft forever preferred_lft forever
```
