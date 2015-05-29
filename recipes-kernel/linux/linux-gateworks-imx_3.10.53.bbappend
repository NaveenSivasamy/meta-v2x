# Copyright (C) 2015 ZENOME Inc.
# Released under the MIT license (see COPYING.MIT for the terms)

FILESEXTRAPATHS_prepend := "${THISDIR}/${PN}-${PV}:"

SRC_URI_append = " \
	file://defconfig \
	file://0001-v2x-add-new-ethernet-and-socket-type-for-WSMP.patch \
"
