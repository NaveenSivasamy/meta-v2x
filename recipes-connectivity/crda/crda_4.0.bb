SUMMARY = "Wireless Central Regulatory Domain Agent"
HOMEPAGE = "http://wireless.kernel.org/en/developers/Regulatory/CRDA"

LICENSE = "copyleft-next-0.3.0"
LIC_FILES_CHKSUM = "file://copyleft-next-0.3.0;md5=8743a2c359037d4d329a31e79eabeffe"

DEPENDS = "python-m2crypto-native python-native libgcrypt libnl"

SRCBRANCH = "meta-v2x"
SRCREV = "2afe164838399ec67439f56288e78cdc925cd1e8"

SRC_URI = " \
	git://github.com/ZENOME/crda.git;branch=${SRCBRANCH} \
	file://do-not-run-ldconfig-if-destdir-is-set.patch \
	file://fix-linking-of-libraries-used-by-reglib.patch \
"

S = "${WORKDIR}/git"

inherit python-dir pythonnative
# Recursive make problem
EXTRA_OEMAKE = "MAKEFLAGS= DESTDIR=${D} LIBDIR=${libdir}/crda LDLIBREG='-Wl,-rpath,${libdir}/crda -lreg'"

do_compile() {
	oe_runmake all_noverify
}

do_install() {
	oe_runmake SBINDIR=${sbindir}/ install
	install -d ${D}${libdir}/crda/
}

RDEPENDS_${PN} = "udev"
FILES_${PN} += "${base_libdir}/udev/rules.d/85-regulatory.rules"
