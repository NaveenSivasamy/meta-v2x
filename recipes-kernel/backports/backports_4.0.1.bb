# Copyright (C) 2015 ZENOME Inc.
# Released under the MIT license (see COPYING.MIT for the terms)

SUMMARY  = "Backporting Linux upstream drivers"
HOMEPAGE = "https://backports.wiki.kernel.org"
SECTION  = "kernel"
LICENSE  = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=d7810fab7487fb0aad327b76f1be7cd7"

EXCLUDE_FROM_WORLD = "1"

SRC_URI = " \
	https://www.kernel.org/pub/linux/kernel/projects/backports/stable/v${PV}/${BPN}-${PV}-1.tar.xz \
	file://defconfig \
	file://0001-define_reinit.patch \
	file://0002-include_vmalloc_h.patch \
	file://0003-ath9k-Add-OCB-mode-support.patch \
"

SRC_URI[md5sum] = "22734fb36f2a3abc6983a3cfaf767436"
SRC_URI[sha256sum] = "71da08c0d2975716b57039b7b9159ab8a882252bf2cac34843b77d2dd6d4cf31"

S = "${WORKDIR}/${BPN}-${PV}-1"

inherit module

EXTRA_OEMAKE = "KLIB_BUILD=${STAGING_KERNEL_BUILDDIR} KLIB=${STAGING_KERNEL_DIR}"

do_configure_prepend() {
	cp ${WORKDIR}/defconfig ${S}/defconfig
}

do_configure_append() {
	make CC=cc -C kconf conf
	make usedefconfig
}

do_install() {
	oe_runmake -C ${STAGING_KERNEL_DIR} M=${S} INSTALL_MOD_PATH=${D} modules_install
}
