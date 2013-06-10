/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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
#ifndef CORE_H
#define CORE_H

enum {
	ATH6KL_USB_PIPE_TX_CTRL = 0,
	ATH6KL_USB_PIPE_TX_DATA_LP,
	ATH6KL_USB_PIPE_TX_DATA_MP,
	ATH6KL_USB_PIPE_TX_DATA_HP,
	ATH6KL_USB_PIPE_RX_CTRL,
	ATH6KL_USB_PIPE_RX_DATA,
	ATH6KL_USB_PIPE_RX_DATA2,
	ATH6KL_USB_PIPE_RX_INT,
	ATH6KL_USB_N_XFERS = 8,
};

enum ath6kl_hif_type {
	ATH6KL_HIF_TYPE_SDIO,
	ATH6KL_HIF_TYPE_USB,
};

enum ath6kl_htc_type {
	ATH6KL_HTC_TYPE_MBOX,
	ATH6KL_HTC_TYPE_PIPE,
};

struct ath6kl_version {
	uint32_t target_ver;
	uint32_t wlan_ver;
	uint32_t abi_ver;
};

struct ath6kl_bmi {
	uint32_t 			cmd_credits;
	bool 				done_sent;
	uint8_t 			*cmd_buf;
	uint32_t 			max_data_size;
	uint32_t			max_cmd_size;
};

struct ath6kl_softc {
	struct ifnet			*sc_ifp;
	device_t			sc_dev;
	struct usb_device		*sc_udev;
	int				sc_iface_index;
	struct mtx			sc_mtx;
	struct ath6kl_version		sc_version;
	uint32_t			sc_target_type;
	struct ath6kl_bmi		sc_bmi;
	const struct ath6kl_hif_ops 	*sc_hif_ops;
	enum ath6kl_hif_type 		sc_hif_type;
	uint32_t                        sc_flags;
#define	ATH6KL_FLAG_INVALID               (1 << 1)
#define	ATH6KL_FLAG_INITDONE              (1 << 2)
	uint32_t			sc_debug;
	struct ath6kl_stat		sc_stat;
};

int ath6kl_core_create(struct ath6kl_softc *);
int ath6kl_core_init(struct ath6kl_softc *, enum ath6kl_htc_type);
void ath6kl_core_cleanup(struct ath6kl_softc *);
void ath6kl_core_destroy(struct ath6kl_softc *);

#endif /* CORE_H */
