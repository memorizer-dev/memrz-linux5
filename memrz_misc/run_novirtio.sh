ROOTFS=memrz_misc/fedora.raw
RESOURCE_DIR=memrz_misc

# sda1 debian
# sda2 fedora

SMP=8
QEMU_MEMORY=15      # Warning: small memory leads to boot problem. No error message will be displayed for those cases.
MEMORIZER_MEMORY=7

GENOPTS="--enable-kvm -m ${QEMU_MEMORY}G"

qemu-system-x86_64 \
    -kernel arch/x86/boot/bzImage -smp $SMP -bios /usr/share/edk2/ovmf/OVMF_CODE.fd \
    -drive file=$ROOTFS -append "console=ttyS0 root=/dev/sda2 rw nokaslr memalloc_size=$MEMORIZER_MEMORY" \
    -nographic $GENOPTS
    