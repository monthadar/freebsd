/*
 * This experimental driver is yet to have a valid license.
 * This driver is ported from/based on several drivers, mainly of which:
 *     o FreeBSD ath(4)
 *     o FreeBSD uath(4)
 *     o Linux ath6kl
 * Please note that license will be update when the driver gets more stable
 * and usable.
 */
#ifndef IF_UATH6KLIOCTL_H
#define IF_UATH6KLIOCTL_H

#include <sys/param.h>

struct ath6kl_stat {
	uint32_t			st_badchunkseqnum;
	uint32_t			st_invalidlen;
	uint32_t			st_multichunk;
	uint32_t			st_toobigrxpkt;
	uint32_t			st_stopinprogress;
	uint32_t			st_crcerr;
	uint32_t			st_phyerr;
	uint32_t			st_decrypt_crcerr;
	uint32_t			st_decrypt_micerr;
	uint32_t			st_decomperr;
	uint32_t			st_keyerr;
	uint32_t			st_err;
	/* CMD/RX/TX queues */
	uint32_t			st_cmd_active;
	uint32_t			st_cmd_inactive;
	uint32_t			st_cmd_pending;
	uint32_t			st_cmd_waiting;
	uint32_t			st_rx_active;
	uint32_t			st_rx_inactive;
	uint32_t			st_tx_active;
	uint32_t			st_tx_inactive;
	uint32_t			st_tx_pending;
};
#define	ATH6KL_STAT_INC(sc, var)		(sc)->sc_stat.var++
#define	ATH6KL_STAT_DEC(sc, var)		(sc)->sc_stat.var--

#endif /* IF_UATH6KLIOCTL_H */
