SUMMARY = "Wireless Regulatory Database"
HOMEPAGE = "http://wireless.kernel.org/en/developers/Regulatory/wireless-regdb"

LICENSE = "ISC"
LIC_FILES_CHKSUM = "file://LICENSE;md5=07c4f6dea3845b02a18dc00c8c87699c"

DEPENDS = "crda"

SRCBRANCH = "meta-v2x"
SRCREV = "85f87d45b916be56db48264531ead8669d0f4061"

SRC_URI = " \
	git://github.com/ZENOME/wireless-regdb.git;branch=${SRCBRANCH} \
"

S = "${WORKDIR}/git"

EXTRA_OEMAKE = ""

do_install() {
	install -d ${D}${libdir}/crda/
	install -m 0644 ${S}/regulatory.bin ${D}${libdir}/crda/regulatory.bin
}

FILES_${PN} += "${libdir}/crda/regulatory.bin"
