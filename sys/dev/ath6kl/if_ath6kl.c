/*-
 * Copyright (c) 2006 Sam Leffler, Errno Consulting
 * Copyright (c) 2008-2009 Weongyo Jeong <weongyo@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */

/*
 * This driver is distantly derived from a driver of the same name
 * by Damien Bergamini.  The original copyright is included below:
 *
 * Copyright (c) 2006
 *	Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This experimental driver is yet to have a valid license.
 * This driver is ported from/based on several drivers, mainly of which:
 *     o FreeBSD ath(4)
 *     o FreeBSD uath(4)
 *     o Linux ath6kl
 * Please note that license will be update when the driver gets more stable
 * and usable.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kdb.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#endif

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_regdomain.h>
#include <net80211/ieee80211_radiotap.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usb_core.h>
#include <dev/usb/usb_device.h>
#include "usbdevs.h"

#include <dev/ath6kl/if_ath6kldebug.h>
#include <dev/ath6kl/if_ath6klvar.h>
#include <dev/ath6kl/if_ath6klreg.h>
#include <dev/ath6kl/if_ath6klioctl.h>
#include <dev/ath6kl/core.h>
#include <dev/ath6kl/hif.h>

static SYSCTL_NODE(_hw_usb, OID_AUTO, ath6kl, CTLFLAG_RW, 0,
    "USB Atheros 6kl series");

#ifdef ATH6KL_DEBUG
uint64_t ath6kl_debug = ATH6KL_DEBUG_ANY;
SYSCTL_QUAD(_hw_usb_ath6kl, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_TUN,
    &ath6kl_debug, 0, "ath6kl debug level");
TUNABLE_QUAD("hw.usb.ath6kl.debug", &ath6kl_debug);
#endif

/* unaligned little endian access */
#define LE_READ_2(p)							\
	((u_int16_t)							\
	 ((((u_int8_t *)(p))[0]      ) | (((u_int8_t *)(p))[1] <<  8)))
#define LE_READ_4(p)							\
	((u_int32_t)							\
	 ((((u_int8_t *)(p))[0]      ) | (((u_int8_t *)(p))[1] <<  8) |	\
	  (((u_int8_t *)(p))[2] << 16) | (((u_int8_t *)(p))[3] << 24)))

/* recognized device vendors/products */
#define USB_PRODUCT_ATHEROS2_AR6004	0x9374
static const STRUCT_USB_HOST_ID ath6kl_devs[] = {
#define	ATH6KL_DEV(v,p) { USB_VP(USB_VENDOR_##v, USB_PRODUCT_##v##_##p) }
	/* TODO: Add more devices later */
	ATH6KL_DEV(ATHEROS2, AR6004)
#undef ATH6KL_DEV
};

/* diagnostic command defnitions */
#define ATH6KL_USB_CONTROL_REQ_SEND_BMI_CMD        1
#define ATH6KL_USB_CONTROL_REQ_RECV_BMI_RESP       2

static int
ath6kl_usb_submit_ctrl_out(struct ath6kl_softc *sc, uint8_t request,
    uint16_t value, uint16_t index, void *data, uint32_t size)
{
	struct usb_device_request req;
	int ret;

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = request;
	USETW(req.wValue, value);
	USETW(req.wIndex, index);
	USETW(req.wLength, size);

	/* send command */
	ret = usbd_do_request_flags(sc->sc_udev, NULL, &req, data,
	    USB_SHORT_XFER_OK, NULL, ATH6KL_CMD_TIMEOUT);

	if (ret != 0) {
		DPRINTF(sc, ATH6KL_DBG_USB, "%s failed,result = %d\n",
		    __func__, ret);
		return ret;
	}

	return 0;
}

static int
ath6kl_usb_submit_ctrl_in(struct ath6kl_softc *sc, uint8_t request,
    uint16_t value, uint16_t index, void *data, uint32_t size)
{
	struct usb_device_request req;
	int ret;

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = request;
	USETW(req.wValue, value);
	USETW(req.wIndex, index);
	USETW(req.wLength, size);

	/* send command */
	ret = usbd_do_request_flags(sc->sc_udev, NULL, &req, data,
	    USB_SHORT_XFER_OK, NULL, 2*ATH6KL_CMD_TIMEOUT);

	if (ret != 0) {
		DPRINTF(sc, ATH6KL_DBG_USB, "%s failed,result = %d\n",
		    __func__, ret);
		return ret;
	}

	return 0;
}

static int
ath6kl_usb_bmi_read(struct ath6kl_softc *sc, uint8_t *buf, uint32_t len)
{
	int ret;

	/* get response */
	ret = ath6kl_usb_submit_ctrl_in(sc,
	    ATH6KL_USB_CONTROL_REQ_RECV_BMI_RESP, 0, 0, buf, len);
	if (ret != 0) {
		ath6kl_err("Unable to read the bmi data from the device: %d\n",
		    ret);
		return ret;
	}

	return 0;
}

static int
ath6kl_usb_bmi_write(struct ath6kl_softc *sc, uint8_t *buf, uint32_t len)
{
	int ret;

	/* send command */
	ret = ath6kl_usb_submit_ctrl_out(sc,
	    ATH6KL_USB_CONTROL_REQ_SEND_BMI_CMD, 0, 0, buf, len);
	if (ret != 0) {
		ath6kl_err("unable to send the bmi data to the device: %d\n",
		    ret);
		return ret;
	}

	return 0;
}

static int
ath6kl_usb_power_on(struct ath6kl_softc *sc)
{

	printf("%s\n", __func__);
	return 0;
}

static int
ath6kl_usb_power_off(struct ath6kl_softc *sc)
{

	printf("%s\n", __func__);
	return 0;
}

static void
ath6kl_usb_stop(struct ath6kl_softc *sc)
{

	printf("%s\n", __func__);
}

static const struct ath6kl_hif_ops ath6kl_usb_ops = {
	.bmi_read = ath6kl_usb_bmi_read,
	.bmi_write = ath6kl_usb_bmi_write,
	.power_on = ath6kl_usb_power_on,
	.power_off = ath6kl_usb_power_off,
	.stop = ath6kl_usb_stop,
};

static int
ath6kl_probe(device_t dev)
{
	struct usb_attach_arg *uaa = device_get_ivars(dev);

	if (uaa->usb_mode != USB_MODE_HOST)
		return (ENXIO);
	if (uaa->info.bConfigIndex != ATH6KL_CONFIG_INDEX)
		return (ENXIO);
	if (uaa->info.bIfaceIndex != ATH6KL_IFACE_INDEX)
		return (ENXIO);

	return (usbd_lookup_id_by_uaa(ath6kl_devs, sizeof(ath6kl_devs), uaa));
}

static int
ath6kl_usb_setup_xfer_resources(struct ath6kl_softc *sc)
{
	struct usb_device *udev = sc->sc_udev;
	struct usb_endpoint *ep;
	uint8_t iface_index = sc->sc_iface_index;
	uint8_t ep_max;

	DPRINTF(sc, ATH6KL_DBG_USB, "%s\n", "setting up USB Pipes using interface");
	ep = udev->endpoints;
	ep_max = udev->endpoints_max;
	while (ep_max--) {
		/* look for matching endpoints */
		if ((iface_index == USB_IFACE_INDEX_ANY) ||
		    (iface_index == ep->iface_index)) {
			switch(ep->edesc->bmAttributes) {
			case UE_ISOCHRONOUS:
				/* TODO for ISO */
				DPRINTF(sc, ATH6KL_DBG_USB,
				   "%s ISOC Ep:0x%2.2X maxpktsz:%d interval:%d\n",
				   UE_GET_DIR(ep->edesc->bEndpointAddress) == UE_DIR_IN ?
				   "RX" : "TX", ep->edesc->bEndpointAddress,
				   UGETW(ep->edesc->wMaxPacketSize), ep->edesc->bInterval);
				break;
			case UE_BULK:
				DPRINTF(sc, ATH6KL_DBG_USB,
				   "%s Bulk Ep:0x%2.2X maxpktsz:%d\n",
				   UE_GET_DIR(ep->edesc->bEndpointAddress) == UE_DIR_IN ?
				   "RX" : "TX", ep->edesc->bEndpointAddress,
				   UGETW(ep->edesc->wMaxPacketSize));
				break;
			case UE_INTERRUPT:
				DPRINTF(sc, ATH6KL_DBG_USB,
				   "%s Int Ep:0x%2.2X maxpktsz:%d interval:%d\n",
				   UE_GET_DIR(ep->edesc->bEndpointAddress) == UE_DIR_IN ?
				   "RX" : "TX", ep->edesc->bEndpointAddress,
				   UGETW(ep->edesc->wMaxPacketSize), ep->edesc->bInterval);
				break;
			default:
				ath6kl_err("Endpoint unkown: %u\n", ep->edesc->bmAttributes);
			}
		}
		ep++;
	}

	return 0;
}

static int
ath6kl_attach(device_t dev)
{
	struct ath6kl_softc *sc = device_get_softc(dev);
	struct usb_attach_arg *uaa = device_get_ivars(dev);
	struct usb_device *udev = uaa->device;
	int ret;

	sc->sc_dev = dev;
	sc->sc_udev = udev;
	sc->sc_iface_index = uaa->info.bIfaceIndex;
#ifdef ATH6KL_DEBUG
	sc->sc_debug = ath6kl_debug;
#endif
	DPRINTF(sc, ATH6KL_DBG_USB, "vendor_id = 0x%04x\n",
	    uaa->info.idVendor);
	DPRINTF(sc, ATH6KL_DBG_USB, "product_id = 0x%04x\n",
	    uaa->info.idProduct);

	switch (usbd_get_speed(udev)) {
		case USB_SPEED_HIGH:
			DPRINTF(sc, ATH6KL_DBG_USB, "%s\n", "USB 2.0 Host");
			break;
		default:
			DPRINTF(sc, ATH6KL_DBG_USB, "%s\n", "USB 1.1 Host");
	}

	device_set_usb_desc(dev);

	mtx_init(&sc->sc_mtx, device_get_nameunit(sc->sc_dev), MTX_NETWORK_LOCK,
	    MTX_DEF);

	ath6kl_usb_setup_xfer_resources(sc);

	ret = ath6kl_core_create(sc);
	if (ret != 0) {
		ath6kl_err("%s\n", "Failed to alloc ath6kl core\n");
		ret = -ENOMEM;
		goto err;
	}

	sc->sc_hif_ops = &ath6kl_usb_ops;
	sc->sc_hif_type = ATH6KL_HIF_TYPE_USB;
	sc->sc_bmi.max_data_size = 252;

	if (ath6kl_core_init(sc, ATH6KL_HTC_TYPE_PIPE)) {
		device_printf(dev, "Could not init core\n");
	}

	device_printf(dev, "Experimental driver: attach always fail!\n");
	ret = EAGAIN;
err:
	mtx_destroy(&sc->sc_mtx);
	return (ret);
}

static int
ath6kl_detach(device_t dev)
{
	struct ath6kl_softc *sc = device_get_softc(dev);

	/*
	 * Prevent further allocations from RX/TX/CMD
	 * data lists and ioctls
	 */
	ATH6KL_LOCK(sc);
	sc->sc_flags |= ATH6KL_FLAG_INVALID;

	/* drain USB transfers */

	/* free data buffers */

	/* free USB transfers and some data buffers */

	/* detach from net80211 */

	mtx_destroy(&sc->sc_mtx);
	return (0);
}

static device_method_t ath6kl_methods[] = {
	DEVMETHOD(device_probe, ath6kl_probe),
	DEVMETHOD(device_attach, ath6kl_attach),
	DEVMETHOD(device_detach, ath6kl_detach),
	DEVMETHOD_END
};
static driver_t ath6kl_driver = {
	.name = "ath6kl",
	.methods = ath6kl_methods,
	.size = sizeof(struct ath6kl_softc)
};
static devclass_t ath6kl_devclass;

DRIVER_MODULE(ath6kl, uhub, ath6kl_driver, ath6kl_devclass, NULL, 0);
MODULE_DEPEND(ath6kl, wlan, 1, 1, 1);
MODULE_DEPEND(ath6kl, usb, 1, 1, 1);
MODULE_VERSION(ath6kl, 1);
