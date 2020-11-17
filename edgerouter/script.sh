#!/bin/sh

source secrets

set firewall all-ping enable
set firewall broadcast-ping disable
set firewall ipv6-receive-redirects disable
set firewall ipv6-src-route disable
set firewall ip-src-route disable
set firewall log-martians enable
set firewall name WAN_IN default-action drop
set firewall name WAN_IN description 'WAN to internal'
set firewall name WAN_IN rule 10 action accept
set firewall name WAN_IN rule 10 description 'Allow established/related'
set firewall name WAN_IN rule 10 state established enable
set firewall name WAN_IN rule 10 state related enable
set firewall name WAN_IN rule 20 action drop
set firewall name WAN_IN rule 20 description 'Drop invalid state'
set firewall name WAN_IN rule 20 state invalid enable
set firewall name WAN_LOCAL default-action drop
set firewall name WAN_LOCAL description 'WAN to router'
set firewall name WAN_LOCAL rule 10 action accept
set firewall name WAN_LOCAL rule 10 description 'Allow established/related'
set firewall name WAN_LOCAL rule 10 state established enable
set firewall name WAN_LOCAL rule 10 state related enable
set firewall name WAN_LOCAL rule 20 action drop
set firewall name WAN_LOCAL rule 20 description 'Drop invalid state'
set firewall name WAN_LOCAL rule 20 state invalid enable
set firewall options mss-clamp mss 1412
set firewall receive-redirects disable
set firewall send-redirects enable
set firewall source-validation disable
set firewall syn-cookies enable
set interfaces ethernet eth0 address 192.168.2.1/24
set interfaces ethernet eth0 duplex auto
set interfaces ethernet eth0 speed auto
set interfaces ethernet eth1 address 192.168.0.1/24
set interfaces ethernet eth1 description Local
set interfaces ethernet eth1 duplex auto
set interfaces ethernet eth1 speed auto
set interfaces ethernet eth2 description 'Local 2'
set interfaces ethernet eth2 disable
set interfaces ethernet eth2 duplex auto
set interfaces ethernet eth2 speed auto
set interfaces ethernet eth3 duplex auto
set interfaces ethernet eth3 speed auto
set interfaces ethernet eth3 vif 35 description 'Internet (PPPoE)'
set interfaces ethernet eth3 vif 35 pppoe 0 default-route auto
set interfaces ethernet eth3 vif 35 pppoe 0 firewall in name WAN_IN
set interfaces ethernet eth3 vif 35 pppoe 0 firewall local name WAN_LOCAL
set interfaces ethernet eth3 vif 35 pppoe 0 mtu 1492
set interfaces ethernet eth3 vif 35 pppoe 0 name-server auto
set interfaces ethernet eth3 vif 35 pppoe 0 password "$ISP_USER"
set interfaces ethernet eth3 vif 35 pppoe 0 user-id "$ISP_PASSWORD"
set interfaces loopback lo
set port-forward auto-firewall enable
set port-forward hairpin-nat enable
set port-forward lan-interface eth0
set port-forward rule 1 description 'Caddy HTTPS'
set port-forward rule 1 forward-to address 192.168.2.2
set port-forward rule 1 forward-to port 8443
set port-forward rule 1 original-port 443
set port-forward rule 1 protocol tcp
set port-forward rule 2 description 'Caddy HTTP'
set port-forward rule 2 forward-to address 192.168.2.2
set port-forward rule 2 forward-to port 8080
set port-forward rule 2 original-port 80
set port-forward rule 2 protocol tcp
set port-forward rule 3 description Wireguard
set port-forward rule 3 forward-to address 192.168.2.2
set port-forward rule 3 forward-to port 51820
set port-forward rule 3 original-port $WIREGUARD_PORT
set port-forward rule 3 protocol udp
set port-forward rule 4 description 'Teamspeak Voice'
set port-forward rule 4 forward-to address 192.168.2.2
set port-forward rule 4 forward-to port 9987
set port-forward rule 4 original-port $TEAMSPEAK_VOICE_PORT
set port-forward rule 4 protocol udp
set port-forward rule 5 description 'Teamspeak Files'
set port-forward rule 5 forward-to address 192.168.2.2
set port-forward rule 5 forward-to port 30033
set port-forward rule 5 original-port $TEAMSPEAK_FILES_PORT
set port-forward rule 5 protocol tcp
set port-forward wan-interface pppoe0
set service dhcp-server disabled false
set service dhcp-server hostfile-update disable
set service dhcp-server shared-network-name DEBUG authoritative disable
set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 default-router 192.168.0.1
set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 dns-server 192.168.0.1
set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 lease 300
set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 start 192.168.0.2 stop 192.168.0.10
set service dhcp-server shared-network-name ETH0 authoritative disable
set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 default-router 192.168.2.1
set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 dns-server 192.168.2.1
set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 lease 3600
set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 start 192.168.2.2 stop 192.168.2.240
set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping zenarch ip-address 192.168.2.2
set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping zenarch mac-address '4c:ed:fb:77:c3:74'
set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping ncase ip-address 192.168.2.3
set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping ncase mac-address '4c:ed:fb:77:c2:9d'
set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping pi ip-address 192.168.2.4
set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping pi mac-address '4c:ed:fb:70:c3:00'
set service dhcp-server static-arp disable
set service dhcp-server use-dnsmasq disable
set service dns forwarding cache-size 0
set service dns forwarding listen-on eth0
set service dns forwarding system
set service nat rule 5010 description 'masquerade for WAN'
set service nat rule 5010 outbound-interface pppoe0
set service nat rule 5010 type masquerade

printf "Setting up SSH server..."
set service ssh listen-address 192.168.2.1
set system login banner pre-login '0x0A connection monitored\n\n'
set system login user "$USER" authentication public-keys desktop key AAAAB3NzaC1yc2EAAAADAQABAAABAQC2JEwHeumCS1IqhE9VIDFTtMSr6vumUdxuEi+ecdnSFFXS36TjeOD0BgI86tLReLQ3ExBJ+uG3NDCIoYrxF/bt42ZNEs627wcFZXUuEV/wgdY1IVrlW/7Wbl3Wl6eECggluzDUxrbrKF5kQPDlkEoAe86XQ/ZEnAB6EORmAQ4aXkIKoe56vndw6H1R+1nmFJfQ8vV8cBOEbHaN0CFOJUnqT3fo/7NRaFBiYJnqRSSBSzBWThc82VJ9QsDr8P+qUoSKaXrvShE/KCoFTNwu+oHqFeTdMUdaUXMRgbHbnAyXps3P7dCsNDV3yyYhvvbEdPBy6Uo6oA76/aLTM4SV3l6R
set system login user "$USER" authentication public-keys desktop type ssh-rsa
set system login user "$USER" authentication public-keys laptop key AAAAB3NzaC1yc2EAAAADAQABAAABAQDGci7qw8oqytim6/t+1h4iDpV5JEHuyLZ/Gaj5kNgG7bcon0BSxwGv5x7cydLxXqaU22MGy0rhD3W0aPIacaWJJyJgaP8hTZ2Pp/IDdg0yoP2fke3A7+qbyNKY4VKa/jYOFUFK4/oZcmR76bp7H6Dx0H3FSF+nJCs66Hae11JhJxxbrbMPB5MUxYeEuOUosAmxE+0tRs9ML3vHW/jQEErJ4UOd3J36c2ZKEdtgi/IWE0ccoxD6ugejPNvKwpMAKyqNC73gckZJYohlY1x0OxzoW+Zb2IQlm/RCh+xTVXEnRm7ym/XpvexFskm8XKOWPYMYVeVRY94oQqsNenL+cEi/
set system login user "$USER" authentication public-keys laptop type ssh-rsa
set system login user "$USER" authentication public-keys phone key AAAAB3NzaC1yc2EAAAADAQABAAABAQDH7TohL9jzrnMYUqUcLpyS9VjhRP4mNyne7QprIOkkiFmFdAqVdfsjkRdAgzuePUTfJ0mUJi6/wLyg9NPFtGNWhgL2opaFSLxeVr9gZIFPRCq6+GifbZb8Ok2iSankPuqe6y7TFnsIwAgoAglYMrGkLfkXPnfLrdG2D+Hea9+og2LuDKHPgg7l1iJ3/vdaeTKpFx17/uXKjpLI6dQb+pkMMYYxHj84FpfPLf+eRaGrdF3PCaUzHT0LUtsJOXD1LTp5RT3uK1FULxHIQnmhN6v3pWnODeFkoCVm5SJDXfyDCNu1wfmXnTqBXF/XSTkhcxQjjCAhTQXI+J0qj0AMUzml
set system login user "$USER" authentication public-keys phone type ssh-rsa
set system login user "$USER" authentication public-keys emergency key AAAAB3NzaC1yc2EAAAADAQABAAABAQC/xzeUPQxLzCfP2EIEVp4yAhhne0xS//PXSgGOwTvKMcafw3qtbeqxptdVreHYimGftYT+1XLYmM/mkXBUx6KGsSzlcOmDRbTSfPZ/IZPAu0kSqWNGd7whIuW/IXU9bQFrvXWM4S9a6kaG+g1RBqnt5pIMJq0JtKhMw44E75paAEtlLq6ssAKss3UApKZ71OJVm9c4yQPZv9nl3NlXpI++aj702+BL3MEEtHurFlFCd838e0QykkwmGkxBZ+ZLnvGft46uirQ3hK5LkG/pFjzKXgPtKUh2ujxicMdLfRfs24PzBhFoQwTzfMDg0NZ+1xZ9ctf1r/YcawodlNljhmmB
set system login user "$USER" authentication public-keys emergency type ssh-rsa
delete service ssh disable-password-authentication
sudo service ssh restart

set service ubnt-discover disable
set service ubnt-discover interface eth3 disable
set service ubnt-discover-server disable
set service unms disable
set system host-name er4
set system login user "$USER" authentication encrypted-password "$HASHED_PASSWORD"
set system login user "$USER" level admin
set system name-server 192.168.2.2
set system ntp server 0.ubnt.pool.ntp.org
set system ntp server 1.ubnt.pool.ntp.org
set system ntp server 2.ubnt.pool.ntp.org
set system ntp server 3.ubnt.pool.ntp.org
set system offload hwnat disable
set system offload ipv4 forwarding enable
set system offload ipv4 pppoe enable
set system package repository wheezy components 'main contrib non-free'
set system package repository wheezy distribution wheezy
set system package repository wheezy password ''
set system package repository wheezy url 'http://archive.debian.org/debian'
set system package repository wheezy username ''
set system static-host-mapping host-name er4.x inet 192.168.2.1
set system static-host-mapping host-name zenarch.x alias photos.x
set system static-host-mapping host-name zenarch.x alias test.x
set system static-host-mapping host-name zenarch.x alias drone.x
set system static-host-mapping host-name zenarch.x inet 192.168.2.2
set system static-host-mapping host-name desktop.x inet 192.168.2.3
set system static-host-mapping host-name desktop.x inet 192.168.2.4
set system syslog global facility all level notice
set system syslog global facility protocols level debug
set system time-zone America/Montreal
set system traffic-analysis custom-category Amazon name Amazon
set system traffic-analysis custom-category Dev name GitHub
set system traffic-analysis custom-category Encrypted name 'DNS over TLS'
set system traffic-analysis custom-category Encrypted name 'Lets Encrypt'
set system traffic-analysis custom-category Google name QUIC
set system traffic-analysis custom-category Google name Google
set system traffic-analysis custom-category Google name 'Google APIs(SSL)'
set system traffic-analysis custom-category TV name Netflix
set system traffic-analysis custom-category denisa name 'Yahoo Mail'
set system traffic-analysis custom-category waste name Instagram
set system traffic-analysis custom-category waste name Facebook
set system traffic-analysis custom-category waste name LinkedIn
set system traffic-analysis dpi enable
set system traffic-analysis export enable
set traffic-control

###############################################
# Start of script
###############################################
printf "Installing packages..."
sudo apt-get update -y
sudo apt-get install -y wget nano
printf "Setting up Shell..."
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
exitOnError $?
printf "done\n"
