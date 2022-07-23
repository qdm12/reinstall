#!/bin/sh

source secrets

TZ=Canada/Eastern
HOSTNAME=zenarch

if [ "$(whoami)" != "root" ]; then
  echo "This script must be run as root"
  exit 1
fi

echo "==> Setting ZFS"
zpool import -a
# Interactive step
until zfs load-key -a && zfs mount -a
do
  echo "Try again"
  sleep 1
done

echo "==> Linking systemd resolver config"
rm /etc/resolv.conf
ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf

echo "==> Setting hostname"
echo "$HOSTNAME" > /etc/hostname
hostnamectl set-hostname "$HOSTNAME"

echo "==> Generating locale"
echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
locale-gen

echo "==> Setting timezone"
pacman -Sy -q --needed --noconfirm tzdata
timedatectl set-timezone "$TZ"

echo "==> Setting SSH server"
mkdir /root/.ssh
chmod 600 /root/.ssh
cat > "/root/.ssh/banner" <<EOL
You are being watched. Behave.
EOL
cat > /etc/ssh/sshd_config <<EOL
Port 22
LoginGraceTime 2m
PermitRootLogin prohibit-password
AllowUsers root
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
Banner /root/.ssh/banner
PrintLastLog yes
Compression delayed
EOL
cat >> "/root/.ssh/authorized_keys" <<EOL
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIEHVK63UVe1Mxb07hI1tVr3EXEiwAw7sMNU4NQ3SGP8 backup
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHvoejMJTIEoicmJCJHop4bq5lLpNL3EXmWW6dHPajct quentin@framework
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFz7WGk+OrrykkIet4iVNbIVD9Kk6XauQaL05nW8OI4h quentin@pixel3
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII9/8+UQc7dAUIVgldXZH3oFxT0QdF6TWUsHEQPTaYeH quentin@o11
EOL
systemctl restart sshd

echo "==> Installing some basic packages"
pacman -Sy -q --needed --noconfirm ca-certificates wget which tree git sudo base-devel mosh

echo "==> Setting up non root user for yay"
useradd -m nonroot
mkdir -p /etc/sudoers.d
echo nonroot ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/nonroot
chmod 0440 /etc/sudoers.d/nonroot
mkdir -p /home/nonroot/.cache
chown nonroot /home/nonroot/.cache

echo "==> Installing yay"
# Note: only Manjaro can install yay with pacman
originPath="$(pwd)"
mkdir /tmp/yay
cd /tmp/yay
git clone --single-branch --depth 1 https://aur.archlinux.org/yay-bin.git .
chown -R nonroot /tmp/yay
sudo -u nonroot makepkg --noconfirm --syncdeps --install --clean
cd "$originPath"
rm -r /tmp/yay /home/nonroot/.cache/*

echo "==> Setting up Shell"
pacman -Sy -q --needed --noconfirm zsh
export EDITOR=nano
export LANG=en_US.UTF-8
usermod --shell /bin/zsh root
wget -qO /root/.zshrc https://raw.githubusercontent.com/qdm12/reinstall/master/arch-server/.zshrc
wget -qO /root/.p10k.zsh https://raw.githubusercontent.com/qdm12/reinstall/master/arch-server/.p10k.zsh
git clone --single-branch --depth 1 https://github.com/robbyrussell/oh-my-zsh.git /root/.oh-my-zsh
git clone --single-branch --depth 1 https://github.com/romkatv/powerlevel10k.git /root/.oh-my-zsh/custom/themes/powerlevel10k
wget -O ~/welcome https://github.com/qdm12/welcome/releases/download/v0.1.0/welcome_0.1.0_linux_amd64
chmod +x ~/welcome

echo "==> Setting up Wireguard"
pacman -Sy -q --needed --noconfirm wireguard-tools

echo "==> Setting Kernel modules"
modprobe zfs nfs nfsd
mkdir -p /etc/modules-load.d/
echo "zfs" >> /etc/modules-load.d/zfs.conf
echo "nfs" >> /etc/modules-load.d/nfs.conf
echo "nfsd" >> /etc/modules-load.d/nfsd.conf

echo "==> Setting Docker"
pacman -Sy -q --needed --noconfirm docker
mkdir -p /etc/docker
echo '{"experimental":true,"data-root":"/mnt/configs/docker-data-root","metrics-addr":"127.0.0.1:9323","log-driver":"loki","log-opts":{"loki-url": "http://127.0.0.1:3100/loki/api/v1/push"},"features":{"buildkit":true}}' > /etc/docker/daemon.json
systemctl start docker
mkdir -p /root/.docker/cli-plugins
docker pull "qmcgaw/binpot:compose-v2.7.0" && \
  containerid="$(docker create qmcgaw/binpot:compose-v2.7.0)" && \
  docker cp "$containerid:/bin" "/root/.docker/cli-plugins/docker-compose" && \
  docker rm "$containerid"
export COMPOSE_DOCKER_CLI_BUILD=1
echo "export COMPOSE_DOCKER_CLI_BUILD=1" >> /root/.zshrc
echo "alias docker-compose='docker compose'" >> /root/.zshrc
# Stored in docker configuration directory:
# docker network create fries --subnet=10.0.0.0/24
# docker plugin install grafana/loki-docker-driver:latest --alias loki --grant-all-permissions
