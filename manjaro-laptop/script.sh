#!/bin/sh

source ./secrets

if [ "$(whoami)" != "root" ]; then
  echo "This script must be run as root"
  exit 1
fi

defaultUser=`users | head -n 1 | cut -f 1 -d' '`
read -p "What's your username [$defaultUser]: " USER
[ -z $USER ] && USER="$defaultUser"

echo "==> Getting the fastest pacman mirror"
sudo pacman-mirrors --continent

echo "==> Upgrading system and packages (might take some time)"
pacman -q -Syu --noconfirm

echo "==> Setting up ssh"
pacman -Sy -q --needed --noconfirm mosh
mkdir -p "/home/$USER/.ssh" "/home/$USER/Desktop" /root/.ssh
ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""
cat > /root/.ssh/known_hosts <<EOL
github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==

EOL
cp -r /root/.ssh "/home/$USER/.ssh"
chmod 700 /root/.ssh "/home/$USER/.ssh"
chmod 400 /root/.ssh/id_rsa "/home/$USER/.ssh/id_rsa"
chown -R $USER "/home/$USER/.ssh"
# TODO launch github.com/settings and show id_rsa.pub

echo "==> Installing some basic packages"
pacman -Sy -q --needed --noconfirm ca-certificates which tree git sudo strace vlc mosh

echo "==> Setting up Git"
pacman -Sy -q --needed --noconfirm git
git config --global user.email "quentin.mcgaw@gmail.com"
git config --global user.name "Quentin McGaw"
git config --global url.ssh://git@github.com/.insteadOf https://github.com/
git config --global core.fileMode false
git config --global core.eof lf
git config --global core.autocrlf input
git config --global core.editor "code --wait"
git config --global pager.branch false
cp /root/.gitconfig "/home/$USER/.gitconfig"
chown $USER "/home/$USER/.gitconfig"
chmod 400 /root/.gitconfig "/home/$USER/.gitconfig"

echo "==> Installing yay"
pacman -Sy -q --needed --noconfirm git base-devel yay

echo "==> Setting up Shell"
usermod --shell /bin/zsh root
usermod --shell /bin/zsh "$USER"
wget -qO /root/.zshrc https://raw.githubusercontent.com/qdm12/reinstall/master/manjaro-laptop/.zshrc
wget -qO /root/.p10k.zsh https://raw.githubusercontent.com/qdm12/reinstall/master/manjaro-laptop/.p10k.zsh
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
mkdir -p /etc/docker
echo '{"experimental": true},"features":{"buildkit":true}' > /etc/docker/daemon.json
usermod -aG docker "$USER"
systemctl enable --now docker
mkdir -p /root/.docker/cli-plugins "/home/$USER/.docker/cli-plugins"
docker pull "qmcgaw/binpot:compose-v2.7.0" && \
  containerid="$(docker create qmcgaw/binpot:compose-v2.7.0)" && \
  docker cp "$containerid:/bin" /root/.docker/cli-plugins/docker-compose && \
  docker rm "$containerid"
cp /root/.docker/cli-plugins/docker-compose "/home/$USER/.docker/cli-plugins/docker-compose"
export COMPOSE_DOCKER_CLI_BUILD=1
echo "export COMPOSE_DOCKER_CLI_BUILD=1" >> /root/.zshrc
echo "export COMPOSE_DOCKER_CLI_BUILD=1" >> "/home/$USER/.zshrc"
echo "alias docker-compose='docker compose'" >> /root/.zshrc
echo "alias docker-compose='docker compose'" >> "/home/$USER/.zshrc"
docker pull qmcgaw/basedevcontainer &
docker pull qmcgaw/godevcontainer &
docker pull qmcgaw/reactdevcontainer &
# TODO login to Docker hub

printf "==> Setting up Wireguard"
pacman -Sy -q --needed --noconfirm wireguard-tools
cat > /etc/wireguard/wg0.conf <<EOL
# TODO: generate wg0.conf with server public keys
# and save local public key to Desktop to save it server side
EOL
#systemctl start wg-quick@wg0.service
#systemctl enable wg-quick@wg0.service

echo "==> Setting up VSCode"
yay -S --noconfirm visual-studio-code-bin
code --install-extension ms-vscode-remote.remote-containers
code --install-extension ms-azuretools.vscode-docker
code --install-extension davidanson.vscode-markdownlint
code --install-extension redhat.vscode-yaml

echo "==> Installing Chrome"
pacman -Sy -q --needed --noconfirm google-chrome

echo "==> Installing VLC"
pacman -Sy -q --needed --noconfirm vlc

echo "==> Installing Parsec"
yay -S --no-confirm parsec-bin

echo "==> Installing Wine"
pacman -Sy -q --needed --noconfirm wine

echo "==> Installing NTFS driver"
pacman -Sy -q --needed --noconfirm ntfs-3g

echo "==> Setting up Go and pprof"
pacman -Sy --noconfirm go graphviz

echo "==> Setting up Slack + Zoom + Discord + screen recorder"
pacman -Sy --noconfirm discord
yay -S --noconfirm slack-desktop zoom simplescreenrecorder

# Framework laptop specific
echo deep | tee /sys/power/mem_sleep
pacman -Sy -q --needed --noconfirm intel_gpu_top libva-utils libva-intel-driver
pacman -Sy -q --needed --noconfirm fprintd
