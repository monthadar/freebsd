/*
 * This experimental driver is yet to have a valid license.
 * This driver is ported from/based on several drivers, mainly of which:
 *     o FreeBSD ath(4)
 *     o FreeBSD uath(4)
 *     o Linux ath6kl
 * Please note that license will be update when the driver gets more stable
 * and usable.
 */
#ifndef IF_UATH6KLDEBUG_H
#define IF_UATH6KLDEBUG_H

#define ATH6KL_DEBUG

#ifdef ATH6KL_DEBUG
#define BIT(x)	(1ULL << (x))
enum {
	ATH6KL_DBG_CREDIT	= BIT(0),
	/* hole */
	ATH6KL_DBG_WLAN_TX     = BIT(2),     /* wlan tx */
	ATH6KL_DBG_WLAN_RX     = BIT(3),     /* wlan rx */
	ATH6KL_DBG_BMI		= BIT(4),     /* bmi tracing */
	ATH6KL_DBG_HTC		= BIT(5),
	ATH6KL_DBG_HIF		= BIT(6),
	ATH6KL_DBG_IRQ		= BIT(7),     /* interrupt processing */
	/* hole */
	/* hole */
	ATH6KL_DBG_WMI         = BIT(10),    /* wmi tracing */
	ATH6KL_DBG_TRC	        = BIT(11),    /* generic func tracing */
	ATH6KL_DBG_SCATTER	= BIT(12),    /* hif scatter tracing */
	ATH6KL_DBG_WLAN_CFG    = BIT(13),    /* cfg80211 i/f file tracing */
	ATH6KL_DBG_RAW_BYTES   = BIT(14),    /* dump tx/rx frames */
	ATH6KL_DBG_AGGR	= BIT(15),    /* aggregation */
	ATH6KL_DBG_SDIO	= BIT(16),
	ATH6KL_DBG_SDIO_DUMP	= BIT(17),
	ATH6KL_DBG_BOOT	= BIT(18),    /* driver init and fw boot */
	ATH6KL_DBG_WMI_DUMP	= BIT(19),
	ATH6KL_DBG_SUSPEND	= BIT(20),
	ATH6KL_DBG_USB		= BIT(21),
	ATH6KL_DBG_USB_BULK	= BIT(22),
	ATH6KL_DBG_RECOVERY	= BIT(23),
	ATH6KL_DEBUG_ANY	= 0xffffffffffffffffULL
};
#undef BIT
extern uint64_t ath6kl_debug;
#define	DPRINTF(m, fmt, ...) do {				\
	if (ath6kl_debug & (m))					\
		printf(fmt, __VA_ARGS__);			\
} while (0)
#define ath6kl_info(fmt, ...)	printf(fmt, __VA_ARGS__);
#define ath6kl_err(fmt, ...)	printf(fmt, __VA_ARGS__);
#define ath6kl_warn(fmt, ...)	printf(fmt, __VA_ARGS__);

#else	/* Not UATH6KL_DEBUG */

#define	DPRINTF(sc, m, fmt, ...) do {				\
	(void) sc;						\
} while (0)
#define ath6kl_info(fmt, ...)
#define ath6kl_err(fmt, ...)
#define ath6kl_warn(fmt, ...)
#endif

#endif /* IF_UATH6KLDEBUG_H */
