# ROOTFS=memrz_misc/fedora.raw
ROOTFS=memrz_misc/debian.qcow2
RESOURCE_DIR=memrz_misc

# sda1 debian
# sda2 fedora

SMP=8
QEMU_MEMORY=15      # Warning: small memory leads to boot problem. No error message will be displayed for those cases.
MEMORIZER_MEMORY=7

NETOPTS="-net nic,model=virtio,macaddr=52:54:00:12:34:56 -net user,hostfwd=tcp:127.0.0.1:$DEBIAN_PORT-:22"
FILEOPTS="-fsdev local,id=fs1,path=$RESOURCE_DIR,security_model=none -device virtio-9p-pci,fsdev=fs1,mount_tag=host-code"
GENOPTS="--enable-kvm -m ${QEMU_MEMORY}G $NETOPTS $FILEOPTS"

qemu-system-x86_64 \
    -kernel arch/x86/boot/bzImage -smp $SMP -bios /usr/share/edk2/ovmf/OVMF_CODE.fd \
    -drive file=$ROOTFS,if=virtio -append "console=ttyS0 root=/dev/vda1 rw nokaslr memalloc_size=$MEMORIZER_MEMORY" \
    -nographic $GENOPTS