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
X11Forwarding yes
EOL
cat >> "/root/.ssh/authorized_keys" <<EOL
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2JEwHeumCS1IqhE9VIDFTtMSr6vumUdxuEi+ecdnSFFXS36TjeOD0BgI86tLReLQ3ExBJ+uG3NDCIoYrxF/bt42ZNEs627wcFZXUuEV/wgdY1IVrlW/7Wbl3Wl6eECggluzDUxrbrKF5kQPDlkEoAe86XQ/ZEnAB6EORmAQ4aXkIKoe56vndw6H1R+1nmFJfQ8vV8cBOEbHaN0CFOJUnqT3fo/7NRaFBiYJnqRSSBSzBWThc82VJ9QsDr8P+qUoSKaXrvShE/KCoFTNwu+oHqFeTdMUdaUXMRgbHbnAyXps3P7dCsNDV3yyYhvvbEdPBy6Uo6oA76/aLTM4SV3l6R desktop
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGci7qw8oqytim6/t+1h4iDpV5JEHuyLZ/Gaj5kNgG7bcon0BSxwGv5x7cydLxXqaU22MGy0rhD3W0aPIacaWJJyJgaP8hTZ2Pp/IDdg0yoP2fke3A7+qbyNKY4VKa/jYOFUFK4/oZcmR76bp7H6Dx0H3FSF+nJCs66Hae11JhJxxbrbMPB5MUxYeEuOUosAmxE+0tRs9ML3vHW/jQEErJ4UOd3J36c2ZKEdtgi/IWE0ccoxD6ugejPNvKwpMAKyqNC73gckZJYohlY1x0OxzoW+Zb2IQlm/RCh+xTVXEnRm7ym/XpvexFskm8XKOWPYMYVeVRY94oQqsNenL+cEi/ laptop
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDH7TohL9jzrnMYUqUcLpyS9VjhRP4mNyne7QprIOkkiFmFdAqVdfsjkRdAgzuePUTfJ0mUJi6/wLyg9NPFtGNWhgL2opaFSLxeVr9gZIFPRCq6+GifbZb8Ok2iSankPuqe6y7TFnsIwAgoAglYMrGkLfkXPnfLrdG2D+Hea9+og2LuDKHPgg7l1iJ3/vdaeTKpFx17/uXKjpLI6dQb+pkMMYYxHj84FpfPLf+eRaGrdF3PCaUzHT0LUtsJOXD1LTp5RT3uK1FULxHIQnmhN6v3pWnODeFkoCVm5SJDXfyDCNu1wfmXnTqBXF/XSTkhcxQjjCAhTQXI+J0qj0AMUzml
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/xzeUPQxLzCfP2EIEVp4yAhhne0xS//PXSgGOwTvKMcafw3qtbeqxptdVreHYimGftYT+1XLYmM/mkXBUx6KGsSzlcOmDRbTSfPZ/IZPAu0kSqWNGd7whIuW/IXU9bQFrvXWM4S9a6kaG+g1RBqnt5pIMJq0JtKhMw44E75paAEtlLq6ssAKss3UApKZ71OJVm9c4yQPZv9nl3NlXpI++aj702+BL3MEEtHurFlFCd838e0QykkwmGkxBZ+ZLnvGft46uirQ3hK5LkG/pFjzKXgPtKUh2ujxicMdLfRfs24PzBhFoQwTzfMDg0NZ+1xZ9ctf1r/YcawodlNljhmmB emergency
EOL
systemctl restart sshd

echo "==> Installing some basic packages"
pacman -Sy -q --needed --noconfirm ca-certificates which tree git sudo base-devel mosh ca-certificates

echo "==> Setting up non root user for yay"
useradd -m nonroot
mkdir -p /etc/sudoers.d
echo nonroot ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/nonroot
chmod 0440 /etc/sudoers.d/nonroot

echo "==> Installing yay"
originPath="$(pwd)"
mkdir /tmp/yay
cd /tmp/yay
git clone --single-branch --depth 1 https://aur.archlinux.org/yay.git .
pacman -Sy -q --needed --noconfirm go
mkdir -p /home/nonroot/.cache
chown -R nonroot /tmp/yay /.cache
sudo -u nonroot makepkg
pacman -R --noconfirm go
pacman -U --noconfirm yay*.tar.zst
cd "$originPath"
rm -r /tmp/yay /home/nonroot/.cache

echo "==> Installing downgrade"
su nonroot -c "yay -Sy --noconfirm downgrade"

echo "==> Setting up Shell"
pacman -Sy -q --needed --noconfirm zsh
export EDITOR=nano
export LANG=en_US.UTF-8
usermod --shell /bin/zsh root
wget -qO /root/.zshrc https://raw.githubusercontent.com/qdm12/reinstall/master/arch-server/.zshrc
wget -qO /root/.p10k.zsh https://raw.githubusercontent.com/qdm12/reinstall/master/arch-server/.p10k.zsh
git clone --single-branch --depth 1 https://github.com/robbyrussell/oh-my-zsh.git /root/.oh-my-zsh
git clone --single-branch --depth 1 https://github.com/romkatv/powerlevel10k.git /root/.oh-my-zsh/custom/themes/powerlevel10k
wget -O ~/welcome https://github.com/qdm12/welcome/releases/download/v0.1.1/welcome_0.1.1_linux_amd64

echo "==> Setting Docker"
pacman -Sy -q --needed --noconfirm docker
echo '{"experimental":true,"data-root":"/mnt/configs/docker-data-root","features":{"buildkit":true}}' > /etc/docker/daemon.json
systemctl enable --now docker
DOCKER_COMPOSE_VERSION=1.27.4
wget -qO /usr/local/bin/docker-compose https://github.com/docker/compose/releases/download/$DOCKER_COMPOSE_VERSION/docker-compose-Linux-x86_64
chmod 500 /usr/local/bin/docker-compose
docker network create fries --subnet=10.0.0.0/24
