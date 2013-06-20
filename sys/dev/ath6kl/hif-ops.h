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
#ifndef HIF_OPS_H
#define HIF_OPS_H

static inline int
ath6kl_hif_bmi_read(struct ath6kl_softc *sc, uint8_t *buf, uint32_t len)
{

	return sc->sc_hif_ops->bmi_read(sc, buf, len);
}

static inline int
ath6kl_hif_bmi_write(struct ath6kl_softc *sc, uint8_t *buf, uint32_t len)
{

	return sc->sc_hif_ops->bmi_write(sc, buf, len);
}

static inline int
ath6kl_hif_power_on(struct ath6kl_softc *sc)
{

	DPRINTF(ATH6KL_DBG_HIF, "%s\n", "hif power on");
	return sc->sc_hif_ops->power_on(sc);
}

static inline int
ath6kl_hif_power_off(struct ath6kl_softc *sc)
{

	DPRINTF(ATH6KL_DBG_HIF, "%s\n", "hif power off");
	return sc->sc_hif_ops->power_off(sc);
}

static inline void
ath6kl_hif_stop(struct ath6kl_softc *sc)
{

	DPRINTF(ATH6KL_DBG_HIF, "%s\n", "hif stop");
	sc->sc_hif_ops->stop(sc);
}

static inline int ath6kl_hif_pipe_send(struct ath6kl_softc *sc,
				       uint8_t pipe, struct mbuf *hdr_buf,
				       struct mbuf *buf)
{
	DPRINTF(ATH6KL_DBG_HIF, "%s\n", "hif pipe send");

	return sc->sc_hif_ops->pipe_send(sc, pipe, hdr_buf, buf);
}

static inline void ath6kl_hif_pipe_get_default(struct ath6kl_softc *sc,
					       uint8_t *ul_pipe, uint8_t *dl_pipe)
{
	DPRINTF(ATH6KL_DBG_HIF, "%s\n", "hif pipe get default");

	sc->sc_hif_ops->pipe_get_default(sc, ul_pipe, dl_pipe);
}

static inline int ath6kl_hif_pipe_map_service(struct ath6kl_softc *sc,
					      uint16_t service_id, uint8_t *ul_pipe,
					      uint8_t *dl_pipe)
{
	DPRINTF(ATH6KL_DBG_HIF, "%s\n", "hif pipe get default");

	return sc->sc_hif_ops->pipe_map_service(sc, service_id, ul_pipe, dl_pipe);
}

static inline uint16_t ath6kl_hif_pipe_get_free_queue_number(struct ath6kl_softc *sc,
							uint8_t pipe)
{
	DPRINTF(ATH6KL_DBG_HIF, "%s\n", "hif pipe get free queue number");

	return sc->sc_hif_ops->pipe_get_free_queue_number(sc, pipe);
}

#endif /* HIF_OPS_H */
