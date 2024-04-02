### ssdfw test ruleset example
 + DNATed service in LAN: public tcp:82 -> lan tcp:80 with reflection
 + docker service on host: `docker run -p 81:80 nginx`
 + host services: ssh, https, http
 + SNAT: eth1 to internet
 + route: eth1 <---> 172.16.6/24 @eth0

```
                               |------------|
 internet<------>||            |nginx 80,443|
                 ||<---eth0--->| ssdfw HOST |<---eth1--->LAN
      LAN<------>||            |dnat 82 --->|--->    (192.168.71/24)
  (172.16.6/24)                |docker 81   |
                               |------------|
```

+ `ssdfw.rules` + separate files in `ssdfw.d`
+ `with-skip.rules` all-in-one file, using **skip**
