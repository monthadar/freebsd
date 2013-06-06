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

int ath6kl_core_init(struct ath6kl_softc *sc, enum ath6kl_htc_type htc_type)
{
	struct ath6kl_bmi_target_info targ_info;
	int ret = 0;

	/* TODO: attach HTC layer */

	ret = ath6kl_bmi_init(sc);
	if (ret)
		goto err;

	/*
	 * Turn on power to get hardware (target) version and leave power
	 * on delibrately as we will boot the hardware anyway within few
	 * seconds.
	 */
	ret = ath6kl_hif_power_on(sc);
	if (ret)
		goto err_bmi_cleanup;

	ret = ath6kl_bmi_get_target_info(sc, &targ_info);
	if (ret)
		goto err_power_off;

	sc->sc_version.target_ver = le32toh(targ_info.version);
	sc->sc_target_type = le32toh(targ_info.type);

	return ret;

err_power_off:
	ath6kl_hif_power_off(sc);
err_bmi_cleanup:
	ath6kl_bmi_cleanup(sc);
err:
	return ret;
}

int
ath6kl_core_create(struct ath6kl_softc *sc)
{

	return 0;
}

void
ath6kl_core_cleanup(struct ath6kl_softc *sc)
{

	printf("%s\n", __func__);
}

void ath6kl_core_destroy(struct ath6kl_softc *sc)
{

	printf("%s\n", __func__);
}
