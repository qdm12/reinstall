#!/bin/vbash
# https://community.ui.com/questions/scripting-script-template-vs-vyatta-cfg-cmd-wrapper-issue/8f098313-6541-4367-9576-6c68127cf85f

# Ensure script is run as group vyattacfg
if [ 'vyattacfg' != $(id -ng) ]; then
  exec sg vyattacfg -c "$0 $@"
fi

source secrets

cw=/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper

$cw begin

# Commands found using `show configuration commands`
$cw set firewall all-ping enable
$cw set firewall broadcast-ping disable
$cw set firewall ipv6-receive-redirects disable
$cw set firewall ipv6-src-route disable
$cw set firewall ip-src-route disable
$cw set firewall log-martians enable
$cw set firewall name WAN_IN default-action drop
$cw set firewall name WAN_IN description 'WAN to internal'
$cw set firewall name WAN_IN rule 10 action accept
$cw set firewall name WAN_IN rule 10 description 'Allow established/related'
$cw set firewall name WAN_IN rule 10 state established enable
$cw set firewall name WAN_IN rule 10 state related enable
$cw set firewall name WAN_IN rule 20 action drop
$cw set firewall name WAN_IN rule 20 description 'Drop invalid state'
$cw set firewall name WAN_IN rule 20 state invalid enable
$cw set firewall name WAN_LOCAL default-action drop
$cw set firewall name WAN_LOCAL description 'WAN to router'
$cw set firewall name WAN_LOCAL rule 10 action accept
$cw set firewall name WAN_LOCAL rule 10 description 'Allow established/related'
$cw set firewall name WAN_LOCAL rule 10 state established enable
$cw set firewall name WAN_LOCAL rule 10 state related enable
$cw set firewall name WAN_LOCAL rule 20 action drop
$cw set firewall name WAN_LOCAL rule 20 description 'Drop invalid state'
$cw set firewall name WAN_LOCAL rule 20 state invalid enable
$cw set firewall options mss-clamp mss 1412
$cw set firewall receive-redirects disable
$cw set firewall send-redirects enable
$cw set firewall source-validation disable
$cw set firewall syn-cookies enable
$cw set interfaces ethernet eth0 address 192.168.2.1/24
$cw set interfaces ethernet eth0 duplex auto
$cw set interfaces ethernet eth0 speed auto
$cw set interfaces ethernet eth1 address 192.168.0.1/24
$cw set interfaces ethernet eth1 description Local
$cw set interfaces ethernet eth1 duplex auto
$cw set interfaces ethernet eth1 speed auto
$cw set interfaces ethernet eth2 description 'Local 2'
$cw set interfaces ethernet eth2 disable
$cw set interfaces ethernet eth2 duplex auto
$cw set interfaces ethernet eth2 speed auto
$cw set interfaces ethernet eth3 duplex auto
$cw set interfaces ethernet eth3 speed auto
$cw set interfaces ethernet eth3 vif 35 description 'Internet (PPPoE)'
$cw set interfaces ethernet eth3 vif 35 pppoe 0 default-route auto
$cw set interfaces ethernet eth3 vif 35 pppoe 0 firewall in name WAN_IN
$cw set interfaces ethernet eth3 vif 35 pppoe 0 firewall local name WAN_LOCAL
$cw set interfaces ethernet eth3 vif 35 pppoe 0 mtu 1492
$cw set interfaces ethernet eth3 vif 35 pppoe 0 name-server auto
$cw set interfaces ethernet eth3 vif 35 pppoe 0 password "$ISP_PASSWORD"
$cw set interfaces ethernet eth3 vif 35 pppoe 0 user-id "$ISP_USER"
$cw set interfaces loopback lo
$cw set port-forward auto-firewall enable
$cw set port-forward hairpin-nat enable
$cw set port-forward lan-interface eth0
$cw set port-forward rule 1 description 'Caddy HTTP'
$cw set port-forward rule 1 forward-to address 192.168.2.2
$cw set port-forward rule 1 forward-to port 8080
$cw set port-forward rule 1 original-port 80
$cw set port-forward rule 1 protocol tcp
$cw set port-forward rule 2 description Wireguard
$cw set port-forward rule 2 forward-to address 192.168.2.2
$cw set port-forward rule 2 forward-to port 51820
$cw set port-forward rule 2 original-port $WIREGUARD_PORT
$cw set port-forward rule 2 protocol udp
$cw set port-forward rule 3 description SSH
$cw set port-forward rule 3 forward-to address 192.168.2.2
$cw set port-forward rule 3 forward-to port 22
$cw set port-forward rule 3 original-port $SSH_PORT
$cw set port-forward rule 3 protocol tcp
$cw set port-forward rule 4 description 'SSH Mosh'
$cw set port-forward rule 4 forward-to address 192.168.2.2
$cw set port-forward rule 4 forward-to port 60001
$cw set port-forward rule 4 original-port $MOSH_PORT
$cw set port-forward rule 4 protocol udp
$cw set port-forward rule 5 description COD4
$cw set port-forward rule 5 forward-to address 192.168.2.2
$cw set port-forward rule 5 forward-to port 28960
$cw set port-forward rule 5 original-port 28960
$cw set port-forward rule 5 protocol udp
$cw set port-forward rule 6 description Syncthing
$cw set port-forward rule 6 forward-to address 192.168.2.2
$cw set port-forward rule 6 forward-to port 22000
$cw set port-forward rule 6 original-port $SYNCTHING_PORT
$cw set port-forward rule 6 protocol tcp
$cw set port-forward rule 7 description 'COD4 slow'
$cw set port-forward rule 7 forward-to address 192.168.2.2
$cw set port-forward rule 7 forward-to port 28961
$cw set port-forward rule 7 original-port 9000
$cw set port-forward rule 7 protocol udp
$cw set port-forward rule 8 description 'Gitea ssh'
$cw set port-forward rule 8 forward-to address 192.168.2.2
$cw set port-forward rule 8 forward-to port 45678
$cw set port-forward rule 8 original-port $GITEA_PORT
$cw set port-forward rule 8 protocol tcp
$cw set port-forward rule 11 description 'Caddy HTTPS'
$cw set port-forward rule 11 forward-to address 192.168.2.2
$cw set port-forward rule 11 forward-to port 8443
$cw set port-forward rule 11 original-port 443
$cw set port-forward rule 11 protocol tcp
$cw set port-forward rule 12 description 'Shadowsocks RO'
$cw set port-forward rule 12 forward-to address 192.168.2.2
$cw set port-forward rule 12 forward-to port 8388
$cw set port-forward rule 12 original-port $SHADOWSOCKS_PORT
$cw set port-forward rule 12 protocol tcp_udp
$cw set port-forward wan-interface pppoe0
$cw set service dhcp-server disabled false
$cw set service dhcp-server hostfile-update disable
$cw set service dhcp-server shared-network-name DEBUG authoritative disable
$cw set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 default-router 192.168.0.1
$cw set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 dns-server 192.168.0.1
$cw set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 lease 300
$cw set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 start 192.168.0.2 stop 192.168.0.5
$cw set service dhcp-server shared-network-name ETH0 authoritative disable
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 default-router 192.168.2.1
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 dns-server 192.168.2.2
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 lease 86400
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 start 192.168.2.2 stop 192.168.2.127
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping o11 ip-address 192.168.2.3
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping o11 mac-address '18:c0:4d:09:f6:63'
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping pi ip-address 192.168.2.4
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping pi mac-address '4c:ed:fb:70:c3:00'
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping zenarch ip-address 192.168.2.2
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping zenarch mac-address 'd8:5e:d3:0f:8b:85'
$cw set service dhcp-server static-arp disable
$cw set service dhcp-server use-dnsmasq disable
$cw set service dns forwarding cache-size 0
$cw set service dns forwarding listen-on eth0
$cw set service dns forwarding system
$cw set service gui http-port 80
$cw set service gui https-port 443
$cw set service gui older-ciphers disable
$cw set service nat rule 5010 description 'masquerade for WAN'
$cw set service nat rule 5010 outbound-interface pppoe0
$cw set service nat rule 5010 type masquerade
$cw set service ssh listen-address 192.168.2.1
$cw set service ssh port 22
$cw set service ssh protocol-version v2
$cw set service ubnt-discover disable
$cw set service ubnt-discover interface eth3 disable
$cw set service ubnt-discover-server disable
$cw set service unms disable
$cw set system host-name ubnt
$cw set system login banner pre-login 'you are being watched\n\n'
$cw set system login user ubnt authentication encrypted-password "$HASHED_PASSWORD"
$cw set system login user ubnt authentication public-keys backup key AAAAC3NzaC1lZDI1NTE5AAAAIIEHVK63UVe1Mxb07hI1tVr3EXEiwAw7sMNU4NQ3SGP8
$cw set system login user ubnt authentication public-keys backup type ssh-ed25519
$cw set system login user ubnt authentication public-keys quentin@framework key AAAAC3NzaC1lZDI1NTE5AAAAIHvoejMJTIEoicmJCJHop4bq5lLpNL3EXmWW6dHPajct
$cw set system login user ubnt authentication public-keys quentin@framework type ssh-ed25519
$cw set system login user ubnt authentication public-keys quentin@o11 key AAAAC3NzaC1lZDI1NTE5AAAAII9/8+UQc7dAUIVgldXZH3oFxT0QdF6TWUsHEQPTaYeH
$cw set system login user ubnt authentication public-keys quentin@o11 type ssh-ed25519
$cw set system login user ubnt level admin
$cw set system name-server 192.168.2.2
$cw set system ntp server 0.ubnt.pool.ntp.org
$cw set system ntp server 1.ubnt.pool.ntp.org
$cw set system ntp server 2.ubnt.pool.ntp.org
$cw set system ntp server 3.ubnt.pool.ntp.org
$cw set system offload hwnat disable
$cw set system offload ipv4 forwarding enable
$cw set system offload ipv4 pppoe enable
$cw set system package repository wheezy components 'main contrib non-free'
$cw set system package repository wheezy distribution wheezy
$cw set system package repository wheezy password ''
$cw set system package repository wheezy url 'http://archive.debian.org/debian'
$cw set system package repository wheezy username ''
$cw set system static-host-mapping
$cw set system syslog global facility all level notice
$cw set system syslog global facility protocols level debug
$cw set system time-zone America/Montreal
$cw set system traffic-analysis dpi disable
$cw set system traffic-analysis export disable
$cw set traffic-control

# Extra commands
$cw set service ssh disable-password-authentication

$cw commit
$cw save
$cw end


###############################################
# Start of script
###############################################
echo "Installing packages..."
sudo apt-get update -y
sudo apt-get install -y wget nano
echo "Setting up Shell..."
export ENV="/home/$USER/.profile"
cat > "$ENV" <<EOL
[ -z "$PS1" ] && return
source /etc/bash_completion.d/vyatta-cfg
source /etc/bash_completion.d/vyatta-op
EDITOR='nano'
LANG=en_US.UTF-8
alias ls='ls -A -F -h'
alias ipt='watch -n 1 -d iptables -nvL'
alias pppoelogs='show interfaces pppoe pppoe0 log'
EOL

echo "done!"
