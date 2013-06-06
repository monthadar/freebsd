/*
 * Copyright (c) 2004-2011 Atheros Communications Inc.
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
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/endian.h>
#include <sys/kdb.h>

#include <dev/ath6kl/if_ath6klvar.h>
#include <dev/ath6kl/if_ath6klreg.h>
#include <dev/ath6kl/if_ath6kldebug.h>
#include <dev/ath6kl/if_ath6klioctl.h>
#include <dev/ath6kl/core.h>
#include <dev/ath6kl/hif.h>
#include <dev/ath6kl/hif-ops.h>
#include <dev/ath6kl/bmi.h>

int
ath6kl_bmi_done(struct ath6kl_softc *sc)
{
	int ret;
	uint32_t cid = BMI_DONE;

	if (sc->sc_bmi.done_sent) {
		DPRINTF(sc, ATH6KL_DBG_BMI, "%s\n", "bmi done skipped");
		return 0;
	}

	sc->sc_bmi.done_sent = true;

	ret = ath6kl_hif_bmi_write(sc, (uint8_t *)&cid, sizeof(cid));
	if (ret) {
		ath6kl_err("Unable to send bmi done: %d\n", ret);
		return ret;
	}

	return 0;
}

int
ath6kl_bmi_get_target_info(struct ath6kl_softc *sc,
    struct ath6kl_bmi_target_info *targ_info)
{
	int ret;
	uint32_t cid = BMI_GET_TARGET_INFO;

	if (sc->sc_bmi.done_sent) {
		ath6kl_err("bmi done sent already, cmd %d disallowed\n", cid);
		return -EACCES;
	}

	ret = ath6kl_hif_bmi_write(sc, (uint8_t *)&cid, sizeof(cid));
	if (ret) {
		ath6kl_err("Unable to send get target info: %d\n", ret);
		return ret;
	}

	if (sc->sc_hif_type == ATH6KL_HIF_TYPE_USB) {
		ret = ath6kl_hif_bmi_read(sc, (uint8_t *)targ_info,
		    sizeof(*targ_info));
	} else {
		ath6kl_err("bmi get tartget type not supported: %d\n",
		    sc->sc_hif_type);
		return ENOTSUP;
	}

	if (ret) {
		ath6kl_err("Unable to recv target info: %d\n", ret);
		return ret;
	}

	DPRINTF(sc, ATH6KL_DBG_BMI, "target info (ver: 0x%x type: 0x%x)\n",
	    targ_info->version, targ_info->type);

	return 0;
}

void
ath6kl_bmi_reset(struct ath6kl_softc *sc)
{

	sc->sc_bmi.done_sent = false;
}

int
ath6kl_bmi_init(struct ath6kl_softc *sc)
{

	if (sc->sc_bmi.max_data_size == 0)
		return -EINVAL;

	/* cmd + addr + len + data_size */
	sc->sc_bmi.max_cmd_size = sc->sc_bmi.max_data_size +
	    (sizeof(uint32_t) * 3);

	sc->sc_bmi.cmd_buf = malloc(sc->sc_bmi.max_cmd_size, M_TEMP,
	    M_NOWAIT | M_ZERO);
	if (!sc->sc_bmi.cmd_buf)
		return -ENOMEM;

	return 0;
}

void
ath6kl_bmi_cleanup(struct ath6kl_softc *sc)
{

	free(sc->sc_bmi.cmd_buf, M_TEMP);
	sc->sc_bmi.cmd_buf = NULL;
}
