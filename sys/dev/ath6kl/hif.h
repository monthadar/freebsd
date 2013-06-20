/*
 * Copyright (c) 2004-2011 Atheros Communications Inc.
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
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
#ifndef HIF_H
#define HIF_H

MALLOC_DECLARE(M_ATH6KL_DEVICE);

struct ath6kl_irq_proc_registers {
	uint8_t host_int_status;
	uint8_t cpu_int_status;
	uint8_t error_int_status;
	uint8_t counter_int_status;
	uint8_t mbox_frame;
	uint8_t rx_lkahd_valid;
	uint8_t host_int_status2;
	uint8_t gmbox_rx_avail;
	uint32_t rx_lkahd[2];
	uint32_t rx_gmbox_lkahd_alias[2];
} __packed;

struct ath6kl_irq_enable_reg {
	uint8_t int_status_en;
	uint8_t cpu_int_status_en;
	uint8_t err_int_status_en;
	uint8_t cntr_int_status_en;
} __packed;

struct ath6kl_device {
	/* protects irq_proc_reg and irq_en_reg below */
	struct mtx lock;
	struct ath6kl_irq_proc_registers irq_proc_reg;
	struct ath6kl_irq_enable_reg irq_en_reg;
	struct htc_target *htc_cnxt;
	struct ath6kl_softc *sc;
};

struct ath6kl_hif_ops {
	int (*bmi_read)(struct ath6kl_softc *, uint8_t *buf, uint32_t len);
	int (*bmi_write)(struct ath6kl_softc *, uint8_t *buf, uint32_t len);
	int (*power_on)(struct ath6kl_softc *);
	int (*power_off)(struct ath6kl_softc *);
	void (*stop)(struct ath6kl_softc *);
	int (*pipe_send)(struct ath6kl_softc *, uint8_t pipe, struct mbuf *,
			 struct mbuf *);
	void (*pipe_get_default)(struct ath6kl_softc *, uint8_t *pipe_ul, uint8_t *pipe_dl);
	int (*pipe_map_service)(struct ath6kl_softc *, uint16_t service_id, uint8_t *pipe_ul,
				uint8_t *pipe_dl);
	uint16_t (*pipe_get_free_queue_number)(struct ath6kl_softc *, uint8_t pipe);
};

#endif	/* HIF_H */
