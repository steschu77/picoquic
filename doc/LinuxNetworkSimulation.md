# Linux Network Simulation #

Setup 1 Mbps:

```
deb-c:~/github/picoquic$ ~/go/bin/comcast --device=enp0s3 --target-bw=1000
sudo tc qdisc show | grep "netem"
sudo tc qdisc add dev enp0s3 handle 10: root htb default 1
sudo tc class add dev enp0s3 parent 10: classid 10:1 htb rate 1000000kbit
sudo tc class add dev enp0s3 parent 10: classid 10:10 htb rate 1000kbit
sudo tc qdisc add dev enp0s3 parent 10:10 handle 100: netem rate 1000kbit
sudo iptables -A POSTROUTING -t mangle -j CLASSIFY --set-class 10:10 -p tcp
sudo iptables -A POSTROUTING -t mangle -j CLASSIFY --set-class 10:10 -p udp
sudo iptables -A POSTROUTING -t mangle -j CLASSIFY --set-class 10:10 -p icmp
sudo ip6tables -A POSTROUTING -t mangle -j CLASSIFY --set-class 10:10 -p tcp
sudo ip6tables -A POSTROUTING -t mangle -j CLASSIFY --set-class 10:10 -p udp
sudo ip6tables -A POSTROUTING -t mangle -j CLASSIFY --set-class 10:10 -p icmp
```

Delete rules:

```
deb-c:~/github/picoquic$ ~/go/bin/comcast --device=enp0s3 --stop
sudo tc qdisc show | grep "netem"
sudo tc qdisc del dev enp0s3 handle 10: root
```
