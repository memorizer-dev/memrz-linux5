

qemu-system-x86_64 -kernel arch/x86/boot/bzImage -m 512 -smp 2 -bios /usr/share/edk2/ovmf/OVMF_CODE.fd \
    -drive format=raw,file=memrz_misc/rootfs.raw -append "console=ttyS0 root=/dev/sda2" \
    -nographic 2>&1 | tee $(dirname $0)/qemu.log