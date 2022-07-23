# Server reinstall

## Arch Linux

### 1. Arch live setup

1. Write an arch iso file in GPT UEFI mode to a key
1. Make sure to disable CSM in the motherboard UEFI
1. Boot from the key
1. Set up a temporary SSH server

    ```sh
    ssh-keygen -A
    passwd
    /usr/bin/sshd -D
    ```

1. On your favourite machine connect to it

    ```sh
    ssh root@<ip-address>
    ```

### 2. Arch base install

1. Set the time with `timedatectl set-ntp true`
1. Create partitions

    ```sh
    fdisk /dev/nvme0n1
    # Delete all partitions
    d,<Enter>,d,<Enter>,d,<Enter>
    # Create GPT table
    g,<Enter>
    # Create EFI partition
    n,<Enter>,<Enter>,+300M
    t,1
    # Create Swap partition
    n,<Enter>,<Enter>,+1G
    t,<Enter>,19
    # Create root partition
    n,<Enter>,<Enter>,<Enter>
    w
    ```

1. Format partitions

    ```sh
    mkfs.fat -F32 /dev/nvme0n1p1
    mkswap /dev/nvme0n1p2
    mkfs.ext4 /dev/nvme0n1p3
    ```

1. Mount the partition

    ```sh
    mount /dev/nvme0n1p3 /mnt
    swapon /dev/nvme0n1p2
    mkdir -p /mnt/boot/EFI
    mount /dev/nvme0n1p1 /boot/EFI
    ```

1. Install base Arch

    ```sh
    pacstrap /mnt base linux linux-firmware amd-ucode nano openssh
    genfstab -U -p /mnt >> /mnt/etc/fstab
    arch-chroot /mnt
    ```

1. Install the boot loader

    ```sh
    pacman -S --noconfirm grub efibootmgr dosfstools os-prober mtools
    grub-install --target=x86_64-efi  --bootloader-id=grub_uefi --recheck
    grub-mkconfig -o /boot/grub/grub.cfg
    # TODO amd-ucode, amd_iommu=on
    ```

1. Ensure DHCP and DNS will work:

    ```sh
    printf "[Match]\nName=en*\n\n[Network]\nLinkLocalAddressing=ipv4\nDHCP=yes\n" > /etc/systemd/network/enp4s0.network
    printf "DNSStubListener=no\n" >> /etc/systemd/resolved.conf
    rm /etc/resolv.conf
    ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl enable systemd-networkd
    systemctl enable systemd-resolved
    ```

1. Setup a temporary ssh server

    ```sh
    passwd
    ssh-keygen -A # TODO remove use from volume
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    systemctl enable sshd
    ```

1. Reboot

    ```sh
    exit
    umount -R /mnt
    poweroff --reboot
    ```

### 3. Further setup

1. Log in to machine with `ssh root@192.168.2.2` using the root password set.
1. Use:

    ```sh
    wget -q https://raw.githubusercontent.com/qdm12/reinstall/master/server/script.sh
    chmod 700 script.sh
    echo "WIREGUARD_PRIVATE_KEY=<insert key here>" > secrets
    ./script.sh
    ```

## Setup ZFS volumes

1. Create the directories

    ```sh
    mkdir -p /mnt/code /mnt/medias /mnt/torrents /mnt/configs /mnt/databases /mnt/logs
    ```

1. Create a SSD pool with

    ```sh
    zpool create -o ashift=12 -o autotrim=on \
    -O compression=lz4 -O normalization=formD \
    -O encryption=aes-256-gcm -O keylocation=prompt -O keyformat=passphrase \
    ssdpool /dev/disk/by-id/ata-KINGSTON_SA400S37240G_50026B76824BB2E1
    ```

1. Create a *database* dataset

    ```sh
    zfs create \
    -o recordsize=8k -o logbias=throughput -o primarycache=metadata \
    -o atime=off -o xattr=sa -o acltype=posixacl \
    -o mountpoint=/mnt/database ssdpool/database
    ```

1. Create a *config* dataset

    ```sh
    zfs create \
    -o atime=off -o xattr=sa -o acltype=posixacl \
    -o mountpoint=/mnt/config ssdpool/config
    ```

1. Create a *log* dataset

    ```sh
    zfs create \
    -o primarycache=metadata \
    -o atime=off -o xattr=sa -o acltype=posixacl \
    -o mountpoint=/mnt/log ssdpool/log
    ```

1. Create a HDD pool with

    ```sh
    zpool create -o ashift=12 \
    -O compression=lz4 -O normalization=formD \
    -O encryption=aes-256-gcm -O keylocation=prompt -O keyformat=passphrase \
    hddpool mirror /dev/disk/by-id/ata-WDC_WD120EFAX-68UNTN0_2AGTJ5XY /dev/disk/by-id/ata-WDC_WD120EFAX-68UNTN0_2AGTR1AY
    ```

1. Create a *torrent* dataset

    ```sh
    zfs create -o recordsize=16k -o atime=off -o mountpoint=/mnt/torrents hddpool/torrents
    ```

1. Create a *medias* dataset

    ```sh
    zfs create -o recordsize=1m -o atime=off -o mountpoint=/mnt/medias hddpool/medias
    ```

## TODOs

- Windows VFIO VM
- Cronjob ZFS status using welcome binary?
- Use error trap to fail the script on any error
- Use Dialog for interactive menus
- Dialog menu for ZFS creation
- In `.profile`:
    - **Volume health with ZFS**
    - CPU temperature, HDDs temperature
    - OpenSSH version
    - Ram usage of Docker
    - Loading spinner
