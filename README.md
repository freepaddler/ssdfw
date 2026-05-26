# ssdfw (Simple Stateful Docker-friendly Firewall)

Simple script, allows to manage docker published ports in IPTABLES the same way as local published ports.

All filtering happens in mangle table: allowed, denied and rejected packets are marked. In INPUT and OUTPUT chains packets are accepted, dropped or rejected by flag set.

This makes setup simple, straightforward and easy to manage. See examples in `iptables` directory.

## Installation

```shell
git clone https://github.com/freepaddler/ssdfw
sudo install -m 755 ssdfw/ssdfw.sh /usr/local/bin/ssdfw
sudo mkdir -p /etc/ssdfw/rules.d
sudo cp ssdfw/iptables/ssdfw.rules /etc/ssdfw/rules
sudo install -D -m 644 ssdfw/systemd/ssdfw.service /etc/systemd/system/ssdfw.service
```

## Setup and run

Place rules in:
+ `/etc/ssdfw/rules`
+ `/etc/ssdfw/rules.d/*.rules`

If `/etc/ssdfw` does not exist, legacy paths are used instead:
+ `/etc/iptables/ssdfw.rules`
+ `/etc/iptables/ssdfw.d/*.rules`

If no rule files are found in the selected location, rules are applied from script itself (yes, they may be also managed).

Run `ssdfw.sh` without args to apply rules. Script will try to use 'iptables-apply' (if found) to be failsafe.
Use `ssdfw apply` to apply rules directly without interactive `iptables-apply` prompts, for example from systemd.

Subcommands (1st arg):
+ `apply`           apply rules directly, without iptables-apply prompts
+ `show`            show all ssdfw rules (iptables -S)
+ `list`            list all ssdfw rules (iptables -L)
+ `flush`           delete ssdfw rules, allow in and out
+ `flush_iptables`  delete all iptables rules, allow in and out

## Rules syntax
Find rules examples in `iptables` directory.

Since _ssdfw.sh_ is just a shell script, working with iptables, then most directives are just vars and functions declared in script itself. 

You can easily use original iptables commands to add custom rules.

### Section NAT IN
Add DNAT rules

+ table: nat
+ chain: PREROUTING

+ directive `$nat_in` to add rule to the section
+ targets:
  + any IPTABLES supported targets (commonly DNAT)

### Section IN
Filters traffic to host itself (including DNATed ports for docker). Use instead of filter INPUT

+ table: mangle
+ chain: PREROUTING
+ directive `$in` to add rule to the section
+ first match target applied (allow, deny, reject, ignore)
+ custom targets:
  + check-state: special directive, MUST exist in `IN` section at least once
    + it ACCEPTs ESTABLISHED and RELATED packets
    + it checks packet destination, if destination is not host itself, then IN processing stops and packet enters IP FORWARD section
  + allow = ACCEPT
  + deny = DROP
  + reject = REJECT (with-reset for tcp)
  + ignore = leave chain without allow/deny decision
  + skip: skip next matching rule for this packet

#### skip example
skip target allows to mark packet to skip next matching rule. designed to be used for straightforward exclusion. The example below excludes `10.0.12/0 `and `10.1.2.3` from dropping by `deny -d 10/8` rule.
```shell
$in -j skip -d 10.0.12/0
$in -j skip -d 10.1.2.3
$in -j deny -d 10/8
```

#### sshguard
`ssdfw` creates a filter table `sshguard` chain and hooks it into `INPUT` before accepting packets marked as allowed. Do not add `sshguard` to `$in`; `$in` rules are added to the mangle table. Just allow SSH in the `IN` section:

```shell
$in -j allow -p tcp --dport 22
```

If `sshguard` is installed and manages the `sshguard` chain, it will be applied by the built-in `INPUT` hook.

### Section IP FORWARD
Filters forwarded traffic (not dedicated to host itself), excluding DNATed ports (docker). Use instead of filter FORWARD

+ table: mangle
+ chain: FORWARD
+ directive `$fwd` to add rule to the section
+ first match target applied (allow, deny, reject, ignore)
+ custom targets:
    + check_fwd_state: optional directive, put it before forward allow/deny rules to ACCEPT ESTABLISHED and RELATED packets
    + allow = ACCEPT
    + deny = DROP
    + reject = REJECT (with-reset for tcp)
    + ignore = leave chain without allow/deny decision
    + skip: skip next matching rule for this packet

`check_fwd_state` is not added automatically. DNATed/docker traffic that was already decided in the `IN` section is protected by built-in rules before user `$fwd` rules are evaluated.

### Section OUT
Filter host outgoing traffic

+ table: filter
+ chain: OUTPUT

+ directive `$out` to add rule to the section
+ targets:
    + any IPTABLES supported targets (ACCEPT, DROP...)

### Section NAT OUT
Manage SNAT and MASQUERADING

+ table: nat
+ chain: POSTROUTING

+ directive `$nat_in` to add rule to the section
+ targets:
    + any IPTABLES supported targets (SNAT, MASQUERADE)

### no_ipv6
I don't deal much with ipv6, that's why script does nothing with it. But some may use `no_ipv6` directive

+ `no_ipv6` DROP all ipv6 traffic, allowing only `lo` interface
+ `no_ipv6 --allow-out` additionally allows any outgoing traffic

## Notes

+ works with bridged docker interfaces (docker+, br-+)
+ docker swarm mode is not tested

## Persistent to reboots

### Alpine Linux
```sh
apk add iptables
ssdfw.sh
rc-service iptables save
rc-service ip6tables save
rc-update add iptables 
rc-update add ip6tables
rc-service iptables start
rc-service ip6tables start
```

### Debian
```shell
sudo apt install iptables
sudo install -D -m 644 ssdfw/systemd/ssdfw.service /etc/systemd/system/ssdfw.service
sudo systemctl daemon-reload
sudo systemctl enable --now ssdfw.service
systemctl status ssdfw.service
```

`iptables-persistent` is not required for ssdfw. The systemd unit applies the rule files at boot with `ssdfw apply`, so `/etc/ssdfw/rules` and `/etc/ssdfw/rules.d/*.rules` remain the source of truth instead of an `iptables-save` snapshot. Legacy `/etc/iptables/ssdfw.rules` and `/etc/iptables/ssdfw.d/*.rules` are used only when `/etc/ssdfw` does not exist.
After changing rule files, run `sudo systemctl reload ssdfw.service` to apply them again.
