#!/bin/sh
## Simple Stateful Docker-friendly Firewall (ssdfw)
## IN -> HOST, IP FORWARD -> routing
## first match hit
set +x

local_ruleset() {

no_ipv6 --allow-out

# --------------- NAT IN ($nat_in -j DNAT) ------------------------------------
# -----------------------------------------------------------------------------

# --------------- IN ($in -j check_state,allow,ignore,skip,deny,reject) -------
$in -j allow    -i lo
$in -j check_state # (MUST appear at least once in IN section)
$in -j deny     -p tcp -m conntrack --ctstate INVALID # tcp scans
$in -j deny     -p tcp ! --syn -m conntrack --ctstate NEW # tcp ack scan
$in -j reject   -p tcp --dport 113     # deny ident
$in -j allow    -p icmp --icmp-type 0  # echo reply
$in -j allow    -p icmp --icmp-type 3  # destination unreachable
$in -j allow    -p icmp --icmp-type 8  # echo request
$in -j allow    -p icmp --icmp-type 11 # ttl exceeded"
$in -j allow    -p icmp --icmp-type 12 # ip bad header"
$in -j deny     -p icmp # dangerous icmp
$in -j deny     -m conntrack ! --ctstate NEW # only new connections accepted
$in -j allow    -p tcp --dport 22 # ssh
# -----------------------------------------------------------------------------

# --------------- IP FORWARD ($fwd -j allow,ignore,skip,deny,reject) ----------
# -----------------------------------------------------------------------------

# --------------- OUT ($out -j ACCEPT,DROP) -----------------------------------
$out -j ACCEPT
$out -m comment --comment "Dropped OUT"
# -----------------------------------------------------------------------------

# ----------------NAT OUT ($nat_out -j MASQUERADE,SNAT)------------------------
# -----------------------------------------------------------------------------
}

# drop ipv6 in
# shellcheck disable=SC2120
no_ipv6() {
    ip6tables -w 3 -P INPUT DROP
    ip6tables -w 3 -P FORWARD DROP
    ip6tables -w 3 -P OUTPUT DROP
    tables="raw mangle nat filter"
    for t in $tables; do
        # flush all rules
        ip6tables -w 3 -F -t "$t"
        # delete all chains
        ip6tables -w 3 -X -t "$t"
    done
    ip6tables -w 3 -A INPUT -j ACCEPT -i lo
    ip6tables -w 3 -A OUTPUT -j ACCEPT -o lo
    if [ "$1" = "--allow-out" ]; then
        ip6tables -w 3 -A INPUT  -j ACCEPT -m conntrack --ctstate ESTABLISHED,RELATED
        ip6tables -w 3 -A OUTPUT -j ACCEPT
    fi
}

usage() {
    cat << EOF
Simple Stateful Docker-friendly Firewall (ssdfw)

    Manages IPTABLES firewall applying rules from:
        - /etc/iptables/ssdfw.rules
        - /etc/iptables/ssdfw.d/*.rules
        - if no files found, then ruleset from this script ($0)

    Running without command applies rules using 'iptables-apply' (if found) to be safe.

    Commands:
        show            show all ssdfw rules (iptables -S)
        list            list all ssdfw rules (iptables -L)
        flush           delete ssdfw rules, allow in and out
        flush_iptables  delete all iptables rules, allow in and out

EOF
}

# read yes/no
yn() (
    # shellcheck disable=SC2039
    # shellcheck disable=SC2030
    read -r -p "$1 [y/N]: " -n 1 a
    echo
    case "$a" in
        y|Y) return 0 ;;
        *) return 1;;
    esac
)

# show ssdfw rules
show() {
    echo "# --------------- NAT IN ------------------------------------------------------"
    iptables -t nat -S nat_in        | grep -v '^-N\|^-P'
    echo
    echo "# --------------- IN ----------------------------------------------------------"
    iptables -t mangle -S PREROUTING | grep -v '^-N\|^-P'
    echo
    echo "# --------------- IP FORWARD --------------------------------------------------"
    iptables -t mangle -S FORWARD    | grep -v '^-N\|^-P'
    echo
    echo "# --------------- OUT ---------------------------------------------------------"
    iptables -t filter -S OUTPUT     | grep -v '^-N\|^-P'
    echo
    echo "# --------------- NAT OUT -----------------------------------------------------"
    iptables -t nat -S nat_out       | grep -v '^-N\|^-P'
}

# list ssdfw rules
list() {
    echo "# --------------- NAT IN ------------------------------------------------------"
    iptables -t nat -vnL nat_in
    echo
    echo "# --------------- IN ----------------------------------------------------------"
    iptables -t mangle -vnL PREROUTING
    echo
    echo "# --------------- IP FORWARD --------------------------------------------------"
    iptables -t mangle -vnL FORWARD
    echo
    echo "# --------------- OUT ---------------------------------------------------------"
    iptables -t filter -vnL OUTPUT
    echo
    echo "# --------------- NAT OUT -----------------------------------------------------"
    iptables -t nat -vnL nat_out
}

# flush ssdfw rules
flush() {
    ! yn "Delete all ssdfw rules and allow unrestricted in and out access?" && return
    set -x
    echo "Flushing ssdfw rules..."
    iptables -P INPUT ACCEPT
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    iptables -t nat -D PREROUTING -j nat_in   2>/dev/null
    iptables -t nat -F nat_in                 2>/dev/null
    iptables -t nat -X nat_in                 2>/dev/null

    iptables -t mangle -F
    iptables -t mangle -X

    iptables -t filter -F INPUT
    iptables -t filter -F DOCKER-USER         2>/dev/null
    iptables -t filter -F OUTPUT

    iptables -t nat -D POSTROUTING -j nat_out 2>/dev/null
    iptables -t nat -F nat_out                2>/dev/null
    iptables -t nat -X nat_out                2>/dev/null

    echo "Done. Use 'ssdfw.sh flush_iptables' to flush ALL IPTABLES rules."
}

# flush all iptables rules
flush_iptables() {
    ! yn "Delete all ALL IPTABLES rules and allow unrestricted in and out access?" && return
    echo "Flushing ALL IPTABLES ip4 rules..."
    # restore default policies
    iptables -P INPUT ACCEPT
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    tables="raw mangle nat filter"
    ## flush all rules and chains
    for t in $tables; do
        # flush all rules
        iptables  -w 3 -F -t "$t"
        ip6tables -w 3 -F -t "$t"
        # delete all chains
        iptables  -w 3 -X -t "$t"
        ip6tables -w 3 -X -t "$t"
    done;
    unset t;
    echo "Done. Restart docker to restore its rules."
}

# shellcheck disable=SC2046
[ $(id -u) -eq 0 ] || {
    echo "ERROR: you must be the super-user (uid 0) to use this utility!"
    exit 1
}

echo
# shellcheck disable=SC2031
case $1 in
    show|list|flush|flush_iptables)
        # shellcheck disable=SC2046
        $1
        exit 0
        ;;
    "") ;;
    *)
        usage
        exit 0
        ;;
esac

# safe run applying rules
grep -q "iptables-apply" "/proc/$PPID/cmdline" || {
    if which iptables-apply >/dev/null; then
        echo "Playing safe, running as: 'iptables-apply -c $0'"
        echo
        exec iptables-apply -c "$0"
    fi
}

ipt="$(which iptables) -w 3" || {
    echo "ERROR: no 'iptables' executable found in PATH"
    exit 1
}

echo "Enabling ip forwarding... (place to sysctl.conf for persistence between reboots)"
sysctl -w net.ipv4.ip_forward=1
[ -f /etc/conf.d/iptables ] && \
    sed -i 's/^(.*)IPFORWARD=(.*)$/IPFORWARD="yes"/g' /etc/conf.d/iptables

private_networks="0.0.0.0/8,127.0.0.0/8"             # loopback
private_networks="$private_networks,10.0.0.0/8"      # RFC 1918 private IP
private_networks="$private_networks,172.16.0.0/12"   # RFC 1918 private IP
private_networks="$private_networks,192.168.0.0/16"  # RFC 1918 private IP
private_networks="$private_networks,169.254.0.0/16"  # DHCP auto-config
private_networks="$private_networks,192.0.2.0/24"    # reserved for docs
private_networks="$private_networks,204.152.64.0/23" # Sun cluster
private_networks="$private_networks,224.0.0.0/3"     # Class D & E multicast

$ipt -P INPUT ACCEPT
$ipt -P FORWARD ACCEPT
$ipt -P OUTPUT ACCEPT

# MARKS
#   0x0FA - Firewall action Allow
#   0x0FC - Firewall action Cancel (reject)
#   0x0FB - Firewall Blacklisted //TODO
#   0x0FD - Firewall action Deny
#   0x5xx - Firewall action Skip

# **** MANGLE
# add skip bits
$ipt -t mangle -N skip 2>/dev/null || $ipt -t mangle -F skip
$ipt -t mangle -A skip -j MARK --or-mark 0x500
# remove skip bits
$ipt -t mangle -N unmark_skip 2>/dev/null || $ipt -t mangle -F unmark_skip
$ipt -t mangle -A unmark_skip -j MARK --and-mark 0x0FF
# check_state
$ipt -t mangle -N check_state 2>/dev/null || $ipt -t mangle -F check_state
$ipt -t mangle -A check_state -g unmark_skip -m mark --mark 0x500/0x500
$ipt -t mangle -A check_state -j MARK --set-mark 0xFA -m conntrack --ctstate ESTABLISHED,RELATED
$ipt -t mangle -A check_state -j ACCEPT -m mark --mark 0xFA/0xFA # accept stateful
# if destination is not host itself (+DNATed services), then IN rules are not applicable
$ipt -t mangle -A check_state -j MARK --set-mark 0x0 -m addrtype ! --dst-type LOCAL
$ipt -t mangle -A check_state -j ACCEPT -m addrtype ! --dst-type LOCAL
# allow = ACCEPT
$ipt -t mangle -N allow 2>/dev/null || $ipt -t mangle -F allow
$ipt -t mangle -A allow -g unmark_skip -m mark --mark 0x500/0x500
$ipt -t mangle -A allow -j MARK --set-mark 0xFA
$ipt -t mangle -A allow -j ACCEPT
# ignore - remove from further checks without decision
$ipt -t mangle -N ignore 2>/dev/null || $ipt -t mangle -F ignore
$ipt -t mangle -A ignore -j unmark_skip -m mark --mark 0x500/0x500
$ipt -t mangle -A ignore -j ACCEPT
# deny = DROP
$ipt -t mangle -N deny 2>/dev/null || $ipt -t mangle -F deny
$ipt -t mangle -A deny -g unmark_skip -m mark --mark 0x500/0x500
$ipt -t mangle -A deny -j MARK --set-mark 0xFD
$ipt -t mangle -A deny -j ACCEPT
# reject (for tcp with tcp-reset)
$ipt -t mangle -N reject 2>/dev/null || $ipt -t mangle -F reject
$ipt -t mangle -A reject -g unmark_skip -m mark --mark 0x500/0x500
$ipt -t mangle -A reject -j MARK --set-mark 0xFC
$ipt -t mangle -A reject -j ACCEPT
# ******** PREROUTING
$ipt -t mangle -F PREROUTING
in="$ipt -t mangle -A PREROUTING"
# ******** FORWARD
$ipt -t mangle -F FORWARD
# skip if mark is already set and DNATed
$ipt -t mangle -A FORWARD -j ACCEPT -m conntrack --ctstate DNAT -m mark --mark 0xF0/0xF0
$ipt -t mangle -A FORWARD -j unmark_skip # if last rule was skip
# shellcheck disable=SC2034
fwd="$ipt -t mangle -A FORWARD"

# **** NAT
# ******** PREROUTING
$ipt -t nat -N nat_in 2>/dev/null || $ipt -t nat -F nat_in
$ipt -t nat -D PREROUTING -j nat_in 2>/dev/null
$ipt -t nat -I PREROUTING -j nat_in
# shellcheck disable=SC2034
nat_in="$ipt -t nat -A nat_in"
# ******** POSTROUTING
$ipt -t nat -N nat_out 2>/dev/null || $ipt -t nat -F nat_out
$ipt -t nat -D POSTROUTING -j nat_out 2>/dev/null
$ipt -t nat -I POSTROUTING -j nat_out
# shellcheck disable=SC2034
nat_out="$ipt -t nat -A nat_out"

# **** FILTER
# ******** INPUT
$ipt -N sshguard 2>/dev/null
$ipt -F INPUT
$ipt -A INPUT -j DROP     -m mark --mark 0xFD/0xFD # denied
$ipt -A INPUT -j REJECT --reject-with tcp-reset -p tcp -m mark --mark 0xFC/0xFC # reject tcp
$ipt -A INPUT -j REJECT   -m mark --mark 0xFC/0xFC # reject other
$ipt -A INPUT -j sshguard -p tcp --dport 22   # sshguard
$ipt -A INPUT -j ACCEPT   -m mark --mark 0xFA/0xFA # allowed
# log all other in
$ipt -A INPUT -m comment --comment "Dropped IN"

# ******** FORWARD
# DOCKER-USER instead of FORWARD
$ipt -N DOCKER-USER 2>/dev/null || $ipt -F DOCKER-USER
$ipt -C FORWARD -j DOCKER-USER 2>/dev/null || $ipt -I FORWARD 1 -j DOCKER-USER
$ipt -A DOCKER-USER -j DROP   -m mark --mark 0xFD/0xFD # denied
$ipt -A DOCKER-USER -j REJECT --reject-with tcp-reset -p tcp -m mark --mark 0xFC/0xFC # rejected tcp
$ipt -A DOCKER-USER -j REJECT -m mark --mark 0xFC/0xFC # rejected other
$ipt -A DOCKER-USER -j ACCEPT -m mark --mark 0xFA/0xFA # allowed
# initiated from docker controlled networks (bridges)
#$ipt -A DOCKER-USER -j RETURN -m conntrack ! --ctstate DNAT -m physdev --physdev-is-in
$ipt -A DOCKER-USER -j RETURN -i docker+ -m conntrack ! --ctstate DNAT
$ipt -A DOCKER-USER -j RETURN -i br-+    -m conntrack ! --ctstate DNAT
# log all other docker-user
$ipt -A DOCKER-USER -m comment --comment "Dropped IP FORWARD"
$ipt -A DOCKER-USER -j DROP

# ******** OUTPUT
out="$ipt -A OUTPUT"
$ipt -F OUTPUT

no_local=""
if [ -r /etc/iptables/ssdfw.rules ]; then
    no_local="1"
    echo "Applying rules from /etc/iptables/ssdfw.rules"
    . /etc/iptables/ssdfw.rules
fi
for rf in /etc/iptables/ssdfw.d/*.rules; do
    [ -f "$rf" ] && {
        no_local="1"
        echo "Applying rules from $rf"
        # shellcheck disable=SC1090
        . "$rf"
    }
done
if [ -z "$no_local" ]; then
    echo "No rules files found. Applying default ruleset"
    local_ruleset
fi

# set default policies
$ipt -P INPUT DROP
$ipt -P FORWARD DROP
$ipt -P OUTPUT DROP

echo
echo "Rules applied. Use 'ssdfw.sh show' to view rules."
echo
