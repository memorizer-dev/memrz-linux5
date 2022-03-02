INITRD=xns_misc/initramfs.cpio.gz

qemu-system-x86_64 -kernel arch/x86/boot/bzImage -m 25G -smp 1 -bios /usr/share/edk2/ovmf/OVMF_CODE.fd \
    -initrd $INITRD -append "console=ttyS0" \
    -nographic 2>&1 | tee $(dirname $0)/qemu.log