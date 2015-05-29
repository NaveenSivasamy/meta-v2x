SUMMARY = "nl80211 based CLI configuration utility for wireless devices"
DESCRIPTION = "iw is a new nl80211 based CLI configuration utility for \
wireless devices. It supports almost all new drivers that have been added \
to the kernel recently. "
HOMEPAGE = "http://wireless.kernel.org/en/users/Documentation/iw"
SECTION = "base"
LICENSE = "BSD"
LIC_FILES_CHKSUM = "file://COPYING;md5=878618a5c4af25e9b93ef0be1a93f774"

DEPENDS = "libnl pkgconfig"

SRC_URI = "http://www.kernel.org/pub/software/network/iw/${BP}.tar.gz \
           file://0001-iw-move-generic-sched-scan-parsing-code-out-of-net-d.patch \
           file://0002-iw-implement-scheduled-scan.patch \
           file://0003-iw-add-support-for-active-scheduled-scan.patch \
           file://0004-iw-add-randomise-option-for-sched_scan.patch \
           file://0005-iw-Print-OSEN-element-for-HotSpot-2.0-IE.patch \
"

SRC_URI[md5sum] = "317aa38edbef95bb0629c021ba5e1a04"
SRC_URI[sha256sum] = "314f8854370f27cdf2855311dd245b68b26b82c0f049cca0519e28c435619f5e"

EXTRA_OEMAKE = ""

do_install() {
    oe_runmake DESTDIR=${D} install
}
