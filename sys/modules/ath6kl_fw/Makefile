#
# $FreeBSD$
#

.PATH: ${.CURDIR}/../../dev/ath6kl

KMOD=		ath6kl_fw

FIRMWS=		ath6klfw_6004_bdata_hw1.3:ath6klfw_6004_bdata_hw1.3:1.3
CLEANFILES=	ath6klfw_6004_bdata_hw1.3

FIRMWS+=	ath6klfw_6004_hw1.3_fw-3:ath6klfw_6004_hw1.3_fw-3:1.3
CLEANFILES+=	ath6klfw_6004_hw1.3_fw-3

ath6klfw_6004_bdata_hw1.3: ${.CURDIR}/../../dev/ath6kl/firmware/AR6004/hw1.3/bdata.uu
	uudecode -p ${.CURDIR}/../../dev/ath6kl/firmware/AR6004/hw1.3/bdata.uu > ${.TARGET}

ath6klfw_6004_hw1.3_fw-3: ${.CURDIR}/../../dev/ath6kl/firmware/AR6004/hw1.3/fw-3.uu
	uudecode -p ${.CURDIR}/../../dev/ath6kl/firmware/AR6004/hw1.3/fw-3.uu > ${.TARGET}


.include <bsd.kmod.mk>

