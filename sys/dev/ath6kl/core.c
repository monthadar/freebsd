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
#include <sys/condvar.h>
#include <sys/sema.h>
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
#include <dev/ath6kl/bmi.h>
#include <dev/ath6kl/target.h>
#include <dev/ath6kl/wmi.h>
#include <dev/ath6kl/core.h>
#include <dev/ath6kl/hif.h>
#include <dev/ath6kl/hif-ops.h>

int ath6kl_core_init(struct ath6kl_softc *sc, enum ath6kl_htc_type htc_type)
{
	struct ath6kl_bmi_target_info targ_info;
	int ret = 0;

	switch (htc_type) {
	case ATH6KL_HTC_TYPE_MBOX:
		/* ath6kl_htc_mbox_attach(ar); */
		printf("unsupported HTC type: ATH6KL_HTC_TYPE_MBOX.\n");
		return EINVAL;
	case ATH6KL_HTC_TYPE_PIPE:
		ath6kl_htc_pipe_attach(sc);
		break;
	default:
		printf("unknown HTC type.\n");
		return EINVAL;
	}

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

	ret = ath6kl_init_hw_params(sc);
	if (ret)
		goto err_power_off;

	/* TODO: create HTC layer */

	ret = ath6kl_init_fetch_firmwares(sc);
	if (ret)
		goto err_htc_cleanup;

	ret = ath6kl_init_hw_start(sc);
	if (ret) {
		ath6kl_err("Failed to start hardware: %d\n", ret);
		goto err_rxbuf_cleanup;
	}

	return ret;

err_rxbuf_cleanup:
err_htc_cleanup:
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
	int ctr;

	sc->sc_p2p = 0;

	sc->sc_vif_max = 1;

	sc->sc_max_norm_iface = 1;

	mtx_init(&sc->sc_lock, "ath6kl_lock", NULL, MTX_DEF);
	mtx_init(&sc->sc_mcastpsq_lock, "ath6kl_mcastpsq_lock",
	    NULL, MTX_DEF);
	mtx_init(&sc->sc_list_lock, "ath6kl_list_lock", NULL, MTX_DEF);

	cv_init(&sc->sc_event_cv, "ath6kl_event_cv");
	mtx_init(&sc->sc_event_mtx, "ath6kl_event_mtx", NULL, MTX_DEF);
	sema_init(&sc->sc_sem, 1, "ath6kl_sem");
	
	TAILQ_INIT(&sc->sc_amsdu_rx_buffer_queue);
	TAILQ_INIT(&sc->sc_vif_list);

	clrbit(&sc->sc_flag, WMI_ENABLED);
	clrbit(&sc->sc_flag, SKIP_SCAN);
	clrbit(&sc->sc_flag, DESTROY_IN_PROGRESS);
	
	sc->sc_tx_pwr = 0;
	sc->sc_intra_bss = 1;
	sc->sc_lrssi_roam_threshold = DEF_LRSSI_ROAM_THRESHOLD;
	
	sc->sc_state = ATH6KL_STATE_OFF;
	
	/* Init the PS queues */
	for (ctr = 0; ctr < AP_MAX_NUM_STA; ctr++) {
		mtx_init(&sc->sc_sta_list[ctr].psq_lock, "ath6kl_psq",
		    NULL, MTX_DEF);
		TAILQ_INIT(&sc->sc_sta_list[ctr].psq);
		TAILQ_INIT(&sc->sc_sta_list[ctr].apsdq);
		sc->sc_sta_list[ctr].mgmt_psq_len = 0;
		TAILQ_INIT(&sc->sc_sta_list[ctr].mgmt_psq);
		sc->sc_sta_list[ctr].aggr_conn =
		    malloc(sizeof(struct aggr_info_conn), M_ATH6KL_AGGR_INFO,
		    M_NOWAIT);
		if (!sc->sc_sta_list[ctr].aggr_conn) {
			ath6kl_err("%s\n", "Failed to allocate memory for "
			    "sta aggregation information\n");
			ath6kl_core_destroy(sc);
			return ENOMEM;
		}
	}
	
	TAILQ_INIT(&sc->sc_mcastpsq);
	
	memcpy(sc->sc_ap_country_code, DEF_AP_COUNTRY_CODE, 3);
	
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
