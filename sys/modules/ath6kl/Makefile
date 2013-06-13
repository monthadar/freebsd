# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/ath6kl

KMOD    = if_ath6kl
SRCS    = if_ath6kl.c if_ath6klvar.h if_ath6klreg.h hif.h core.c core.h\
	  hif-ops.h if_ath6klioctl.h if_ath6kldebug.h bmi.c bmi.h\
	  bus_if.h device_if.h init.c target.h\
	  opt_bus.h opt_usb.h usb_if.h usbdevs.h

.include <bsd.kmod.mk>
