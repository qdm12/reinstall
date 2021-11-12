#!/bin/sh

source ./secrets

TZ=Canada/Eastern

if [ "$(whoami)" != "root" ]; then
  echo "This script must be run as root"
  exit 1
fi

defaultUser=`users | head -n 1 | cut -f 1 -d' '`
read -p "What's your username [$defaultUser]: " USER
[ -z $USER ] && USER="$defaultUser"

read -p "Hostname: " HOSTNAME
if [ -z $HOSTNAME ]; then
  echo "You must set a non empty hostname"
  exit 1
fi

echo "==> Getting the fastest pacman mirror"
sudo pacman-mirrors --continent

echo "==> Upgrading system and packages (might take some time)"
pacman -q -Syu --noconfirm

echo "==> Setting hostname"
echo "$HOSTNAME" > /etc/hostname
hostnamectl set-hostname "$HOSTNAME"

echo "==> Generating locale"
echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
locale-gen

echo "==> Setting timezone"
pacman -Sy -q --needed --noconfirm tzdata
timedatectl set-timezone "$TZ"

echo "==> Setting up ssh"
mkdir -p "/home/$USER/.ssh" "/home/$USER/Desktop" /root/.ssh
ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""
cat > /root/.ssh/known_hosts <<EOL
github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==

EOL
cp -r /root/.ssh "/home/$USER/.ssh"
chmod 700 /root/.ssh "/home/$USER/.ssh"
chmod 400 /root/.ssh/id_rsa "/home/$USER/.ssh/id_rsa"
chown -R $USER "/home/$USER/.ssh"
cp -f "/home/$USER/.ssh/id_rsa.pub" "/home/$USER/Desktop/"
echo "YOUR SSH PUBLIC KEY id_rsa.pub IS SAVED ON YOUR DESKTOP"
# TODO launch github.com/settings and show id_rsa.pub

echo "==> Installing some basic packages"
pacman -Sy -q --needed --noconfirm ca-certificates tree vlc base-devel

echo "==> Setting up Git"
pacman -Sy -q --needed --noconfirm git
git config --global user.email "quentin.mcgaw@districtm.net"
git config --global user.name "Quentin McGaw"
git config --global url.ssh://git@github.com/.insteadOf https://github.com/
cp /root/.gitconfig "/home/$USER/.gitconfig"
chown $USER "/home/$USER/.gitconfig"
chmod 400 /root/.gitconfig "/home/$USER/.gitconfig"

echo "==> Installing yay"
originPath="$(pwd)"
mkdir /tmp/yay
cd /tmp/yay
git clone --single-branch --depth 1 https://aur.archlinux.org/yay.git .
pacman -Sy -q --needed --noconfirm go
mkdir -p "/home/$USER/.cache"
chown -R "$USER" /tmp/yay /.cache
sudo -u nonroot makepkg
pacman -R --noconfirm go
pacman -U --noconfirm yay*.tar.zst
cd "$originPath"
rm -r /tmp/yay "/home/$USER/.cache"

echo "==> Installing downgrade"
su "$USER" -c "yay -Sy --noconfirm downgrade"

echo "==> Setting up Shell"
pacman -Sy -q --needed --noconfirm zsh
export EDITOR=nano
export LANG=en_US.UTF-8
usermod --shell /bin/zsh root
usermod --shell /bin/zsh "$USER"
wget -qO /root/.zshrc https://raw.githubusercontent.com/qdm12/reinstall/master/manjaro-work/.zshrc
wget -qO /root/.p10k.zsh https://raw.githubusercontent.com/qdm12/reinstall/master/manjaro-work/.p10k.zsh
git clone --single-branch --depth 1 https://github.com/robbyrussell/oh-my-zsh.git /root/.oh-my-zsh
git clone --single-branch --depth 1 https://github.com/romkatv/powerlevel10k.git /root/.oh-my-zsh/custom/themes/powerlevel10k
wget -O ~/welcome https://github.com/qdm12/welcome/releases/download/v0.1.0/welcome_0.1.0_linux_amd64
chmod +x ~/welcome
cp -f /root/.zshrc "/home/$USER/"
cp -f /root/.p10k.zsh "/home/$USER/"
cp -r /root/.oh-my-zsh "/home/$USER/"
cp -f /root/welcome "/home/$USER/welcome"
chown -R "$USER" "/home/$USER/"
chmod -R 700 "/home/$USER/"

echo "==> Setting Docker"
pacman -Sy -q --needed --noconfirm docker
echo '{"experimental": true},"features":{"buildkit":true}' > /etc/docker/daemon.json
usermod -aG docker "$USER"
systemctl enable --now docker
DOCKER_COMPOSE_VERSION=1.27.4
wget -qO /usr/local/bin/docker-compose https://github.com/docker/compose/releases/download/$DOCKER_COMPOSE_VERSION/docker-compose-Linux-x86_64
chmod 500 /usr/local/bin/docker-compose
chown "$USER" /usr/local/bin/docker-compose

echo "==> Setting up VSCode"
yay -S --noconfirm visual-studio-code-bin
code --install-extension ms-vscode-remote.remote-containers
code --install-extension ms-azuretools.vscode-docker
code --install-extension davidanson.vscode-markdownlint
code --install-extension redhat.vscode-yaml

echo "==> Setting up Go and pprof"
pacman -Sy --noconfirm go graphviz

echo "==> Setting up Slack + Zoom + Discord + screen recorder"
pacman -Sy --noconfirm discord
yay -S --noconfirm slack-desktop zoom simplescreenrecorder

echo "==> Setting up Google Cloud SDK"
yay -S --noconfirm google-cloud-sdk
gcloud auth login
gcloud container clusters get-credentials dmx-us-east-12 --region us-east1 --project dmx-cluster
gcloud container clusters get-credentials dmx-us-east-15 --region us-east1 --project dmx-cluster
gcloud container clusters get-credentials dmx-us-east-16 --region us-east1 --project dmx-cluster
gcloud container clusters get-credentials dmx-us-east-17 --region us-east1 --project dmx-cluster
