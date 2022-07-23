#!/bin/vbash
# https://community.ui.com/questions/scripting-script-template-vs-vyatta-cfg-cmd-wrapper-issue/8f098313-6541-4367-9576-6c68127cf85f

# Ensure script is run as group vyattacfg
if [ 'vyattacfg' != $(id -ng) ]; then
  exec sg vyattacfg -c "$0 $@"
fi

source secrets

cw=/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper

$cw begin
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
$cw set interfaces ethernet eth3 vif 35 pppoe 0 password "$ISP_USER"
$cw set interfaces ethernet eth3 vif 35 pppoe 0 user-id "$ISP_PASSWORD"
$cw set interfaces loopback lo
$cw set port-forward auto-firewall enable
$cw set port-forward hairpin-nat enable
$cw set port-forward lan-interface eth0
$cw set port-forward rule 1 description 'Caddy HTTPS'
$cw set port-forward rule 1 forward-to address 192.168.2.2
$cw set port-forward rule 1 forward-to port 8443
$cw set port-forward rule 1 original-port 443
$cw set port-forward rule 1 protocol tcp
$cw set port-forward rule 2 description 'Caddy HTTP'
$cw set port-forward rule 2 forward-to address 192.168.2.2
$cw set port-forward rule 2 forward-to port 8080
$cw set port-forward rule 2 original-port 80
$cw set port-forward rule 2 protocol tcp
$cw set port-forward rule 3 description Wireguard
$cw set port-forward rule 3 forward-to address 192.168.2.2
$cw set port-forward rule 3 forward-to port 51820
$cw set port-forward rule 3 original-port $WIREGUARD_PORT
$cw set port-forward rule 3 protocol udp
$cw set port-forward rule 4 description 'Teamspeak Voice'
$cw set port-forward rule 4 forward-to address 192.168.2.2
$cw set port-forward rule 4 forward-to port 9987
$cw set port-forward rule 4 original-port $TEAMSPEAK_VOICE_PORT
$cw set port-forward rule 4 protocol udp
$cw set port-forward rule 5 description 'Teamspeak Files'
$cw set port-forward rule 5 forward-to address 192.168.2.2
$cw set port-forward rule 5 forward-to port 30033
$cw set port-forward rule 5 original-port $TEAMSPEAK_FILES_PORT
$cw set port-forward rule 5 protocol tcp
$cw set port-forward wan-interface pppoe0
$cw set service dhcp-server disabled false
$cw set service dhcp-server hostfile-update disable
$cw set service dhcp-server shared-network-name DEBUG authoritative disable
$cw set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 default-router 192.168.0.1
$cw set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 dns-server 192.168.0.1
$cw set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 lease 300
$cw set service dhcp-server shared-network-name DEBUG subnet 192.168.0.0/24 start 192.168.0.2 stop 192.168.0.10
$cw set service dhcp-server shared-network-name ETH0 authoritative disable
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 default-router 192.168.2.1
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 dns-server 192.168.2.1
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 lease 3600
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 start 192.168.2.2 stop 192.168.2.240
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping zenarch ip-address 192.168.2.2
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping zenarch mac-address '4c:ed:fb:77:c3:74'
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping ncase ip-address 192.168.2.3
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping ncase mac-address '4c:ed:fb:77:c2:9d'
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping pi ip-address 192.168.2.4
$cw set service dhcp-server shared-network-name ETH0 subnet 192.168.2.0/24 static-mapping pi mac-address '4c:ed:fb:70:c3:00'
$cw set service dhcp-server static-arp disable
$cw set service dhcp-server use-dnsmasq disable
$cw set service dns forwarding cache-size 0
$cw set service dns forwarding listen-on eth0
$cw set service dns forwarding system
$cw set service nat rule 5010 description 'masquerade for WAN'
$cw set service nat rule 5010 outbound-interface pppoe0
$cw set service nat rule 5010 type masquerade

echo "Setting up SSH server..."
$cw set service ssh listen-address 192.168.2.1
$cw set system login banner pre-login '0x0A connection monitored\n\n'
$cw set system login user "$USER" authentication public-keys desktop key AAAAB3NzaC1yc2EAAAADAQABAAABAQC2JEwHeumCS1IqhE9VIDFTtMSr6vumUdxuEi+ecdnSFFXS36TjeOD0BgI86tLReLQ3ExBJ+uG3NDCIoYrxF/bt42ZNEs627wcFZXUuEV/wgdY1IVrlW/7Wbl3Wl6eECggluzDUxrbrKF5kQPDlkEoAe86XQ/ZEnAB6EORmAQ4aXkIKoe56vndw6H1R+1nmFJfQ8vV8cBOEbHaN0CFOJUnqT3fo/7NRaFBiYJnqRSSBSzBWThc82VJ9QsDr8P+qUoSKaXrvShE/KCoFTNwu+oHqFeTdMUdaUXMRgbHbnAyXps3P7dCsNDV3yyYhvvbEdPBy6Uo6oA76/aLTM4SV3l6R
$cw set system login user "$USER" authentication public-keys desktop type ssh-rsa
$cw set system login user "$USER" authentication public-keys laptop key AAAAB3NzaC1yc2EAAAADAQABAAABAQDGci7qw8oqytim6/t+1h4iDpV5JEHuyLZ/Gaj5kNgG7bcon0BSxwGv5x7cydLxXqaU22MGy0rhD3W0aPIacaWJJyJgaP8hTZ2Pp/IDdg0yoP2fke3A7+qbyNKY4VKa/jYOFUFK4/oZcmR76bp7H6Dx0H3FSF+nJCs66Hae11JhJxxbrbMPB5MUxYeEuOUosAmxE+0tRs9ML3vHW/jQEErJ4UOd3J36c2ZKEdtgi/IWE0ccoxD6ugejPNvKwpMAKyqNC73gckZJYohlY1x0OxzoW+Zb2IQlm/RCh+xTVXEnRm7ym/XpvexFskm8XKOWPYMYVeVRY94oQqsNenL+cEi/
$cw set system login user "$USER" authentication public-keys laptop type ssh-rsa
$cw set system login user "$USER" authentication public-keys phone key AAAAB3NzaC1yc2EAAAADAQABAAABAQDH7TohL9jzrnMYUqUcLpyS9VjhRP4mNyne7QprIOkkiFmFdAqVdfsjkRdAgzuePUTfJ0mUJi6/wLyg9NPFtGNWhgL2opaFSLxeVr9gZIFPRCq6+GifbZb8Ok2iSankPuqe6y7TFnsIwAgoAglYMrGkLfkXPnfLrdG2D+Hea9+og2LuDKHPgg7l1iJ3/vdaeTKpFx17/uXKjpLI6dQb+pkMMYYxHj84FpfPLf+eRaGrdF3PCaUzHT0LUtsJOXD1LTp5RT3uK1FULxHIQnmhN6v3pWnODeFkoCVm5SJDXfyDCNu1wfmXnTqBXF/XSTkhcxQjjCAhTQXI+J0qj0AMUzml
$cw set system login user "$USER" authentication public-keys phone type ssh-rsa
$cw set system login user "$USER" authentication public-keys emergency key AAAAB3NzaC1yc2EAAAADAQABAAABAQC/xzeUPQxLzCfP2EIEVp4yAhhne0xS//PXSgGOwTvKMcafw3qtbeqxptdVreHYimGftYT+1XLYmM/mkXBUx6KGsSzlcOmDRbTSfPZ/IZPAu0kSqWNGd7whIuW/IXU9bQFrvXWM4S9a6kaG+g1RBqnt5pIMJq0JtKhMw44E75paAEtlLq6ssAKss3UApKZ71OJVm9c4yQPZv9nl3NlXpI++aj702+BL3MEEtHurFlFCd838e0QykkwmGkxBZ+ZLnvGft46uirQ3hK5LkG/pFjzKXgPtKUh2ujxicMdLfRfs24PzBhFoQwTzfMDg0NZ+1xZ9ctf1r/YcawodlNljhmmB
$cw set system login user "$USER" authentication public-keys emergency type ssh-rsa
$cw set service ssh disable-password-authentication
sudo service ssh restart

$cw set service ubnt-discover disable
$cw set service ubnt-discover interface eth3 disable
$cw set service ubnt-discover-server disable
$cw set service unms disable
$cw set system host-name er4
$cw set system login user "$USER" authentication encrypted-password "$HASHED_PASSWORD"
$cw set system login user "$USER" level admin
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
$cw set system static-host-mapping host-name er4.x inet 192.168.2.1
$cw set system static-host-mapping host-name zenarch.x alias photos.x
$cw set system static-host-mapping host-name zenarch.x alias test.x
$cw set system static-host-mapping host-name zenarch.x alias drone.x
$cw set system static-host-mapping host-name zenarch.x inet 192.168.2.2
$cw set system static-host-mapping host-name desktop.x inet 192.168.2.3
$cw set system static-host-mapping host-name desktop.x inet 192.168.2.4
$cw set system syslog global facility all level notice
$cw set system syslog global facility protocols level debug
$cw set system time-zone America/Montreal
$cw set system traffic-analysis custom-category Amazon name Amazon
$cw set system traffic-analysis custom-category Dev name GitHub
$cw set system traffic-analysis custom-category Encrypted name 'DNS over TLS'
$cw set system traffic-analysis custom-category Encrypted name 'Lets Encrypt'
$cw set system traffic-analysis custom-category Google name QUIC
$cw set system traffic-analysis custom-category Google name Google
$cw set system traffic-analysis custom-category Google name 'Google APIs(SSL)'
$cw set system traffic-analysis custom-category TV name Netflix
$cw set system traffic-analysis custom-category denisa name 'Yahoo Mail'
$cw set system traffic-analysis custom-category waste name Instagram
$cw set system traffic-analysis custom-category waste name Facebook
$cw set system traffic-analysis custom-category waste name LinkedIn
$cw set system traffic-analysis dpi enable
$cw set system traffic-analysis export enable
$cw set traffic-control

$cw commit
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
exitOnError $?
echo "done!"
