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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/sema.h>
#include <sys/taskqueue.h>
#include <sys/systm.h>
#include <sys/linker.h>
#include <sys/firmware.h>

#include <net80211/ieee80211.h>

#include <dev/ath6kl/wmi.h>
#include <dev/ath6kl/common.h>
#include <dev/ath6kl/htc.h>

MALLOC_DECLARE(M_ATH6KL_FW);
MALLOC_DECLARE(M_ATH6KL_AGGR_INFO);

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

/* USB endpoint definitions */
#define ATH6KL_USB_EP_ADDR_APP_CTRL_IN          0x81
#define ATH6KL_USB_EP_ADDR_APP_DATA_IN          0x82
#define ATH6KL_USB_EP_ADDR_APP_DATA2_IN         0x83
#define ATH6KL_USB_EP_ADDR_APP_INT_IN           0x84

#define ATH6KL_USB_EP_ADDR_APP_CTRL_OUT         0x01
#define ATH6KL_USB_EP_ADDR_APP_DATA_LP_OUT      0x02
#define ATH6KL_USB_EP_ADDR_APP_DATA_MP_OUT      0x03
#define ATH6KL_USB_EP_ADDR_APP_DATA_HP_OUT      0x04

#define MAX_ATH6KL                        1
#define ATH6KL_MAX_RX_BUFFERS             16
#define ATH6KL_BUFFER_SIZE                1664
#define ATH6KL_MAX_AMSDU_RX_BUFFERS       4
#define ATH6KL_AMSDU_REFILL_THRESHOLD     3
#define ATH6KL_AMSDU_BUFFER_SIZE     (WMI_MAX_AMSDU_RX_DATA_FRAME_LENGTH + 128)
#define MAX_MSDU_SUBFRAME_PAYLOAD_LEN	1508
#define MIN_MSDU_SUBFRAME_PAYLOAD_LEN	46

#define USER_SAVEDKEYS_STAT_INIT     0
#define USER_SAVEDKEYS_STAT_RUN      1

#define ATH6KL_TX_TIMEOUT      10
#define ATH6KL_MAX_ENDPOINTS   4
#define MAX_NODE_NUM           15

#define ATH6KL_APSD_ALL_FRAME		0xFFFF
#define ATH6KL_APSD_NUM_OF_AC		0x4
#define ATH6KL_APSD_FRAME_MASK		0xF

/* Extra bytes for htc header alignment */
#define ATH6KL_HTC_ALIGN_BYTES 3

/* MAX_HI_COOKIE_NUM are reserved for high priority traffic */
#define MAX_DEF_COOKIE_NUM                180
#define MAX_HI_COOKIE_NUM                 18	/* 10% of MAX_COOKIE_NUM */
#define MAX_COOKIE_NUM                 (MAX_DEF_COOKIE_NUM + MAX_HI_COOKIE_NUM)

#define MAX_DEFAULT_SEND_QUEUE_DEPTH      (MAX_DEF_COOKIE_NUM / WMM_NUM_AC)

#define DISCON_TIMER_INTVAL               10000  /* in msec */

/* Channel dwell time in fg scan */
#define ATH6KL_FG_SCAN_INTERVAL		50 /* in ms */

/* includes also the null byte */
#define ATH6KL_FIRMWARE_MAGIC               "QCA-ATH6KL"

enum ath6kl_fw_ie_type {
	ATH6KL_FW_IE_FW_VERSION = 0,
	ATH6KL_FW_IE_TIMESTAMP = 1,
	ATH6KL_FW_IE_OTP_IMAGE = 2,
	ATH6KL_FW_IE_FW_IMAGE = 3,
	ATH6KL_FW_IE_PATCH_IMAGE = 4,
	ATH6KL_FW_IE_RESERVED_RAM_SIZE = 5,
	ATH6KL_FW_IE_CAPABILITIES = 6,
	ATH6KL_FW_IE_PATCH_ADDR = 7,
	ATH6KL_FW_IE_BOARD_ADDR = 8,
	ATH6KL_FW_IE_VIF_MAX = 9,
};

enum ath6kl_fw_capability {
	ATH6KL_FW_CAPABILITY_HOST_P2P = 0,
	ATH6KL_FW_CAPABILITY_SCHED_SCAN = 1,

	/*
	 * Firmware is capable of supporting P2P mgmt operations on a
	 * station interface. After group formation, the station
	 * interface will become a P2P client/GO interface as the case may be
	 */
	ATH6KL_FW_CAPABILITY_STA_P2PDEV_DUPLEX,

	/*
	 * Firmware has support to cleanup inactive stations
	 * in AP mode.
	 */
	ATH6KL_FW_CAPABILITY_INACTIVITY_TIMEOUT,

	/* Firmware has support to override rsn cap of rsn ie */
	ATH6KL_FW_CAPABILITY_RSN_CAP_OVERRIDE,

	/*
	 * Multicast support in WOW and host awake mode.
	 * Allow all multicast in host awake mode.
	 * Apply multicast filter in WOW mode.
	 */
	ATH6KL_FW_CAPABILITY_WOW_MULTICAST_FILTER,

	/* Firmware supports enhanced bmiss detection */
	ATH6KL_FW_CAPABILITY_BMISS_ENHANCE,

	/*
	 * FW supports matching of ssid in schedule scan
	 */
	ATH6KL_FW_CAPABILITY_SCHED_SCAN_MATCH_LIST,

	/* Firmware supports filtering BSS results by RSSI */
	ATH6KL_FW_CAPABILITY_RSSI_SCAN_THOLD,

	/* FW sets mac_addr[4] ^= 0x80 for newly created interfaces */
	ATH6KL_FW_CAPABILITY_CUSTOM_MAC_ADDR,

	/* Firmware supports TX error rate notification */
	ATH6KL_FW_CAPABILITY_TX_ERR_NOTIFY,

	/* supports WMI_SET_REGDOMAIN_CMDID command */
	ATH6KL_FW_CAPABILITY_REGDOMAIN,

	/* Firmware supports sched scan decoupled from host sleep */
	ATH6KL_FW_CAPABILITY_SCHED_SCAN_V2,

	/*
	 * Firmware capability for hang detection through heart beat
	 * challenge messages.
	 */
	ATH6KL_FW_CAPABILITY_HEART_BEAT_POLL,

	/* this needs to be last */
	ATH6KL_FW_CAPABILITY_MAX,
};

#if 0
/* XXX: not sure what this is meant to do */
#define ATH6KL_CAPABILITY_LEN (ALIGN(ATH6KL_FW_CAPABILITY_MAX, 32) / 32)
#endif
#define ATH6KL_CAPABILITY_LEN (ATH6KL_FW_CAPABILITY_MAX)

struct ath6kl_fw_ie {
	uint32_t id;
	uint32_t len;
	uint8_t data[0];
};

#define BIT(x)	(1ULL << (x))
enum ath6kl_hw_flags {
	ATH6KL_HW_64BIT_RATES		= BIT(0),
	ATH6KL_HW_AP_INACTIVITY_MINS	= BIT(1),
	ATH6KL_HW_MAP_LP_ENDPOINT	= BIT(2),
	ATH6KL_HW_SDIO_CRC_ERROR_WAR	= BIT(3),
};
#undef BIT

#define ATH6KL_FW_API2_FILE "fw-2"
#define ATH6KL_FW_API3_FILE "fw-3"
#define ATH6KL_FW_API4_FILE "fw-4"

/* AR6003 1.0 definitions */
#define AR6003_HW_1_0_VERSION                 0x300002ba

/* AR6003 2.0 definitions */
#define AR6003_HW_2_0_VERSION                 0x30000384
#define AR6003_HW_2_0_PATCH_DOWNLOAD_ADDRESS  0x57e910
#define AR6003_HW_2_0_FW_DIR			"ath6k/AR6003/hw2.0"
#define AR6003_HW_2_0_OTP_FILE			"otp.bin.z77"
#define AR6003_HW_2_0_FIRMWARE_FILE		"athwlan.bin.z77"
#define AR6003_HW_2_0_TCMD_FIRMWARE_FILE	"athtcmd_ram.bin"
#define AR6003_HW_2_0_PATCH_FILE		"data.patch.bin"
#define AR6003_HW_2_0_BOARD_DATA_FILE AR6003_HW_2_0_FW_DIR "/bdata.bin"
#define AR6003_HW_2_0_DEFAULT_BOARD_DATA_FILE \
			AR6003_HW_2_0_FW_DIR "/bdata.SD31.bin"

/* AR6003 3.0 definitions */
#define AR6003_HW_2_1_1_VERSION                 0x30000582
#define AR6003_HW_2_1_1_FW_DIR			"ath6k/AR6003/hw2.1.1"
#define AR6003_HW_2_1_1_OTP_FILE		"otp.bin"
#define AR6003_HW_2_1_1_FIRMWARE_FILE		"athwlan.bin"
#define AR6003_HW_2_1_1_TCMD_FIRMWARE_FILE	"athtcmd_ram.bin"
#define AR6003_HW_2_1_1_UTF_FIRMWARE_FILE	"utf.bin"
#define AR6003_HW_2_1_1_TESTSCRIPT_FILE	"nullTestFlow.bin"
#define AR6003_HW_2_1_1_PATCH_FILE		"data.patch.bin"
#define AR6003_HW_2_1_1_BOARD_DATA_FILE AR6003_HW_2_1_1_FW_DIR "/bdata.bin"
#define AR6003_HW_2_1_1_DEFAULT_BOARD_DATA_FILE	\
			AR6003_HW_2_1_1_FW_DIR "/bdata.SD31.bin"

/* AR6004 1.0 definitions */
#define AR6004_HW_1_0_VERSION                 0x30000623
#define AR6004_HW_1_0_FW_DIR			"ath6k/AR6004/hw1.0"
#define AR6004_HW_1_0_FIRMWARE_FILE		"fw.ram.bin"
#define AR6004_HW_1_0_BOARD_DATA_FILE         AR6004_HW_1_0_FW_DIR "/bdata.bin"
#define AR6004_HW_1_0_DEFAULT_BOARD_DATA_FILE \
	AR6004_HW_1_0_FW_DIR "/bdata.DB132.bin"

/* AR6004 1.1 definitions */
#define AR6004_HW_1_1_VERSION                 0x30000001
#define AR6004_HW_1_1_FW_DIR			"ath6k/AR6004/hw1.1"
#define AR6004_HW_1_1_FIRMWARE_FILE		"fw.ram.bin"
#define AR6004_HW_1_1_BOARD_DATA_FILE         AR6004_HW_1_1_FW_DIR "/bdata.bin"
#define AR6004_HW_1_1_DEFAULT_BOARD_DATA_FILE \
	AR6004_HW_1_1_FW_DIR "/bdata.DB132.bin"

/* AR6004 1.2 definitions */
#define AR6004_HW_1_2_VERSION                 0x300007e8
#define AR6004_HW_1_2_FW_DIR			"ath6k/AR6004/hw1.2"
#define AR6004_HW_1_2_FIRMWARE_FILE           "fw.ram.bin"
#define AR6004_HW_1_2_BOARD_DATA_FILE         AR6004_HW_1_2_FW_DIR "/bdata.bin"
#define AR6004_HW_1_2_DEFAULT_BOARD_DATA_FILE \
	AR6004_HW_1_2_FW_DIR "/bdata.bin"

/* AR6004 1.3 definitions */
/*
 * XXX: AR6004_HW_1_3_FW_DIR is not pointing to a directory anymore,
 * instead it is the prefix for the firmware image that is loaded using
 * firmware_register. Consider changing name to somthing similar to
 * AR6004_HW_1_3_FW_PREFIX.
 */
#define AR6004_HW_1_3_VERSION			0x31c8088a
#define AR6004_HW_1_3_FW_DIR			"ath6klfw_6004_hw1.3"
#define AR6004_HW_1_3_FIRMWARE_FILE		"ath6klfw_6004_fw_hw1.3"
#define AR6004_HW_1_3_BOARD_DATA_FILE		"ath6klfw_6004_bdata_hw1.3"
#define AR6004_HW_1_3_DEFAULT_BOARD_DATA_FILE	"ath6klfw_6004_default_bdata_hw1.3"

/* Per STA data, used in AP mode */
#define BIT(x)	(1ULL << (x))
#define STA_PS_AWAKE		BIT(0)
#define	STA_PS_SLEEP		BIT(1)
#define	STA_PS_POLLED		BIT(2)
#define STA_PS_APSD_TRIGGER     BIT(3)
#define STA_PS_APSD_EOSP        BIT(4)
#undef BIT

/* HTC TX packet tagging definitions */
#define ATH6KL_CONTROL_PKT_TAG    HTC_TX_PACKET_TAG_USER_DEFINED
#define ATH6KL_DATA_PKT_TAG       (ATH6KL_CONTROL_PKT_TAG + 1)

#define AR6003_CUST_DATA_SIZE 16

#define AGGR_WIN_IDX(x, y)          ((x) % (y))
#define AGGR_INCR_IDX(x, y)         AGGR_WIN_IDX(((x) + 1), (y))
#define AGGR_DCRM_IDX(x, y)         AGGR_WIN_IDX(((x) - 1), (y))
#define ATH6KL_MAX_SEQ_NO		0xFFF
#define ATH6KL_NEXT_SEQ_NO(x)		(((x) + 1) & ATH6KL_MAX_SEQ_NO)

#define NUM_OF_TIDS         8
#define AGGR_SZ_DEFAULT     8

#define AGGR_WIN_SZ_MIN     2
#define AGGR_WIN_SZ_MAX     8

#define TID_WINDOW_SZ(_x)   ((_x) << 1)

#define AGGR_NUM_OF_FREE_NETBUFS    16

#define AGGR_RX_TIMEOUT     100	/* in ms */

#define WMI_TIMEOUT (2 * HZ)

#define MBOX_YIELD_LIMIT 99

#define ATH6KL_DEFAULT_LISTEN_INTVAL	100 /* in TUs */
#define ATH6KL_DEFAULT_BMISS_TIME	1500
#define ATH6KL_MAX_WOW_LISTEN_INTL	300 /* in TUs */
#define ATH6KL_MAX_BMISS_TIME		5000

/* configuration lags */
/*
 * ATH6KL_CONF_IGNORE_ERP_BARKER: Ignore the barker premable in
 * ERP IE of beacon to determine the short premable support when
 * sending (Re)Assoc req.
 * ATH6KL_CONF_IGNORE_PS_FAIL_EVT_IN_SCAN: Don't send the power
 * module state transition failure events which happen during
 * scan, to the host.
 */
#define BIT(x)	(1ULL << (x))
#define ATH6KL_CONF_IGNORE_ERP_BARKER		BIT(0)
#define ATH6KL_CONF_IGNORE_PS_FAIL_EVT_IN_SCAN  BIT(1)
#define ATH6KL_CONF_ENABLE_11N			BIT(2)
#define ATH6KL_CONF_ENABLE_TX_BURST		BIT(3)
#define ATH6KL_CONF_UART_DEBUG			BIT(4)
#undef bit
#define P2P_WILDCARD_SSID_LEN			7 /* DIRECT- */

struct ath6kl_buff {
	struct mbuf 			*br_m;
	TAILQ_ENTRY(ath6kl_buff)	bf_entries;
};
typedef TAILQ_HEAD(, ath6kl_buff) ath6kl_buff_head;

enum wlan_low_pwr_state {
	WLAN_POWER_STATE_ON,
	WLAN_POWER_STATE_CUT_PWR,
	WLAN_POWER_STATE_DEEP_SLEEP,
	WLAN_POWER_STATE_WOW
};

enum sme_state {
	SME_DISCONNECTED,
	SME_CONNECTING,
	SME_CONNECTED
};

struct mbuf_hold_q {
	struct mbuf 	*m;
	bool 		is_amsdu;
	uint16_t 	seq_no;
};

struct rxtid {
	bool aggr;
	bool timer_mon;
	uint16_t win_sz;
	uint16_t seq_next;
	uint32_t hold_q_sz;
	struct skb_hold_q *hold_q;
	ath6kl_buff_head q;

	/*
	 * lock mainly protects seq_next and hold_q. Movement of seq_next
	 * needs to be protected between aggr_timeout() and
	 * aggr_process_recv_frm(). hold_q will be holding the pending
	 * reorder frames and it's access should also be protected.
	 * Some of the other fields like hold_q_sz, win_sz and aggr are
	 * initialized/reset when receiving addba/delba req, also while
	 * deleting aggr state all the pending buffers are flushed before
	 * resetting these fields, so there should not be any race in accessing
	 * these fields.
	 */
	struct mtx lock;
};

struct rxtid_stats {
	uint32_t num_into_aggr;
	uint32_t num_dups;
	uint32_t num_oow;
	uint32_t num_mpdu;
	uint32_t num_amsdu;
	uint32_t num_delivered;
	uint32_t num_timeouts;
	uint32_t num_hole;
	uint32_t num_bar;
};

struct aggr_info_conn {
	uint8_t aggr_sz;
	uint8_t timer_scheduled;
	struct callout timer;
// 	struct net_device *dev;
	struct rxtid rx_tid[NUM_OF_TIDS];
	struct rxtid_stats stat[NUM_OF_TIDS];
	struct aggr_info *aggr_info;
};

struct aggr_info {
	struct aggr_info_conn *aggr_conn;
	ath6kl_buff_head rx_amsdu_freeq;
};

struct ath6kl_wep_key {
	uint8_t key_index;
	uint8_t key_len;
	uint8_t key[64];
};

#define ATH6KL_KEY_SEQ_LEN 8

struct ath6kl_key {
	uint8_t key[WLAN_MAX_KEY_LEN];
	uint8_t key_len;
	uint8_t seq[ATH6KL_KEY_SEQ_LEN];
	uint8_t seq_len;
	uint32_t cipher;
};

struct ath6kl_node_mapping {
	uint8_t mac_addr[IEEE80211_ADDR_LEN];
	uint8_t ep_id;
	uint8_t tx_pend;
};

struct ath6kl_cookie {
	struct sk_buff *skb;
	uint32_t map_no;
// 	struct htc_packet htc_pkt;
	struct ath6kl_cookie *arc_list_next;
};

struct ath6kl_mgmt_buff {
	TAILQ_ENTRY(ath6kl_mgmt_buff) list;
	uint32_t freq;
	uint32_t wait;
	uint32_t id;
	bool no_cck;
	size_t len;
	uint8_t buf[0];
};

struct ath6kl_sta {
	uint16_t sta_flags;
	uint8_t mac[IEEE80211_ADDR_LEN];
	uint8_t aid;
	uint8_t keymgmt;
	uint8_t ucipher;
	uint8_t auth;
	uint8_t wpa_ie[ATH6KL_MAX_IE];
	ath6kl_buff_head psq;

	/* protects psq, mgmt_psq, apsdq, and mgmt_psq_len fields */
	struct mtx psq_lock;

	TAILQ_HEAD(, ath6kl_mgmt_buff) mgmt_psq;
	size_t mgmt_psq_len;
	uint8_t apsd_info;
	ath6kl_buff_head apsdq;
	struct aggr_info_conn *aggr_conn;
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

struct target_stats {
	uint64_t tx_pkt;
	uint64_t tx_byte;
	uint64_t tx_ucast_pkt;
	uint64_t tx_ucast_byte;
	uint64_t tx_mcast_pkt;
	uint64_t tx_mcast_byte;
	uint64_t tx_bcast_pkt;
	uint64_t tx_bcast_byte;
	uint64_t tx_rts_success_cnt;
	uint64_t tx_pkt_per_ac[4];

	uint64_t tx_err;
	uint64_t tx_fail_cnt;
	uint64_t tx_retry_cnt;
	uint64_t tx_mult_retry_cnt;
	uint64_t tx_rts_fail_cnt;

	uint64_t rx_pkt;
	uint64_t rx_byte;
	uint64_t rx_ucast_pkt;
	uint64_t rx_ucast_byte;
	uint64_t rx_mcast_pkt;
	uint64_t rx_mcast_byte;
	uint64_t rx_bcast_pkt;
	uint64_t rx_bcast_byte;
	uint64_t rx_frgment_pkt;

	uint64_t rx_err;
	uint64_t rx_crc_err;
	uint64_t rx_key_cache_miss;
	uint64_t rx_decrypt_err;
	uint64_t rx_dupl_frame;

	uint64_t tkip_local_mic_fail;
	uint64_t tkip_cnter_measures_invoked;
	uint64_t tkip_replays;
	uint64_t tkip_fmt_err;
	uint64_t ccmp_fmt_err;
	uint64_t ccmp_replays;

	uint64_t pwr_save_fail_cnt;

	uint64_t cs_bmiss_cnt;
	uint64_t cs_low_rssi_cnt;
	uint64_t cs_connect_cnt;
	uint64_t cs_discon_cnt;

	int32_t tx_ucast_rate;
	int32_t rx_ucast_rate;

	uint32_t lq_val;

	uint32_t wow_pkt_dropped;
	uint16_t wow_evt_discarded;

	int16_t noise_floor_calib;
	int16_t cs_rssi;
	int16_t cs_ave_beacon_rssi;
	uint8_t cs_ave_beacon_snr;
	uint8_t cs_last_roam_msec;
	uint8_t cs_snr;

	uint8_t wow_host_pkt_wakeups;
	uint8_t wow_host_evt_wakeups;

	uint32_t arp_received;
	uint32_t arp_matched;
	uint32_t arp_replied;
};

struct ath6kl_mbox_info {
	uint32_t htc_addr;
	uint32_t htc_ext_addr;
	uint32_t htc_ext_sz;

	uint32_t block_size;

	uint32_t gmbox_addr;

	uint32_t gmbox_sz;
};

/*
 * 802.11i defines an extended IV for use with non-WEP ciphers.
 * When the EXTIV bit is set in the key id byte an additional
 * 4 bytes immediately follow the IV for TKIP.  For CCMP the
 * EXTIV bit is likewise set but the 8 bytes represent the
 * CCMP header rather than IV+extended-IV.
 */

#define ATH6KL_KEYBUF_SIZE 16
#define ATH6KL_MICBUF_SIZE (8+8)	/* space for both tx and rx */

#define ATH6KL_KEY_XMIT  0x01
#define ATH6KL_KEY_RECV  0x02
#define ATH6KL_KEY_DEFAULT   0x80	/* default xmit key */

/* Initial group key for AP mode */
struct ath6kl_req_key {
	bool valid;
	uint8_t key_index;
	int key_type;
	uint8_t key[WLAN_MAX_KEY_LEN];
	uint8_t key_len;
};

enum ath6kl_hif_type {
	ATH6KL_HIF_TYPE_SDIO,
	ATH6KL_HIF_TYPE_USB,
};

enum ath6kl_htc_type {
	ATH6KL_HTC_TYPE_MBOX,
	ATH6KL_HTC_TYPE_PIPE,
};

/* Max number of filters that hw supports */
#define ATH6K_MAX_MC_FILTERS_PER_LIST 7
struct ath6kl_mc_filter {
	TAILQ_ENTRY(ath6kl_mc_filter) list;
	char hw_addr[ATH6KL_MCAST_FILTER_MAC_ADDR_SIZE];
};

struct ath6kl_htcap {
	bool ht_enable;
	uint8_t ampdu_factor;
	unsigned short cap_info;
};

/*
 * Driver's maximum limit, note that some firmwares support only one vif
 * and the runtime (current) limit must be checked from ar->vif_max.
 */
#define ATH6KL_VIF_MAX	3

/* vif flags info */
enum ath6kl_vif_state {
	CONNECTED,
	CONNECT_PEND,
	WMM_ENABLED,
	NETQ_STOPPED,
	DTIM_EXPIRED,
	NETDEV_REGISTERED,
	CLEAR_BSSFILTER_ON_BEACON,
	DTIM_PERIOD_AVAIL,
	WLAN_ENABLED,
	STATS_UPDATE_PEND,
	HOST_SLEEP_MODE_CMD_PROCESSED,
	NETDEV_MCAST_ALL_ON,
	NETDEV_MCAST_ALL_OFF,
	SCHED_SCANNING,
};

/* XXX: find a good replacement */
#define ATH6KL_IEEE80211_NUM_BANDS	3

struct ath6kl_vif {
	TAILQ_ENTRY(ath6kl_vif) list;
// 	struct wireless_dev wdev;
// 	struct net_device *ndev;
	struct ath6kl_softc *ar;
	/* Lock to protect vif specific net_stats and flags */
	struct mtx if_lock;
	uint8_t fw_vif_idx;
	unsigned long flags;
	int ssid_len;
	uint8_t ssid[IEEE80211_NWID_LEN];
	uint8_t dot11_auth_mode;
	uint8_t auth_mode;
	uint8_t prwise_crypto;
	uint8_t prwise_crypto_len;
	uint8_t grp_crypto;
	uint8_t grp_crypto_len;
	uint8_t def_txkey_index;
	uint8_t next_mode;
	uint8_t nw_type;
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint8_t req_bssid[IEEE80211_ADDR_LEN];
	uint16_t ch_hint;
	uint16_t bss_ch;
	struct ath6kl_wep_key wep_key_list[WMI_MAX_KEY_INDEX + 1];
	struct ath6kl_key keys[WMI_MAX_KEY_INDEX + 1];
	struct aggr_info *aggr_cntxt;
	struct ath6kl_htcap htcap[ATH6KL_IEEE80211_NUM_BANDS];

	struct callout disconnect_timer;
	struct callout sched_scan_timer;

// 	struct cfg80211_scan_request *scan_req;
	enum sme_state sme_state;
	int reconnect_flag;
	uint32_t last_roc_id;
	uint32_t last_cancel_roc_id;
	uint32_t send_action_id;
	bool probe_req_report;
	uint16_t assoc_bss_beacon_int;
	uint16_t listen_intvl_t;
	uint16_t bmiss_time_t;
	uint32_t txe_intvl;
	uint16_t bg_scan_period;
	uint8_t assoc_bss_dtim_period;
// 	struct net_device_stats net_stats;
	struct target_stats target_stats;
	struct wmi_connect_cmd profile;
	uint16_t rsn_capab;

	TAILQ_HEAD(, ath6kl_mc_filter) mc_filter;
};

#define WOW_LIST_ID		0
#define WOW_HOST_REQ_DELAY	500 /* ms */

#define ATH6KL_SCHED_SCAN_RESULT_DELAY 5000 /* ms */

/* Flag info */
enum ath6kl_dev_state {
	WMI_ENABLED,
	WMI_READY,
	WMI_CTRL_EP_FULL,
	TESTMODE,
	DESTROY_IN_PROGRESS,
	SKIP_SCAN,
	ROAM_TBL_PEND,
	FIRST_BOOT,
	RECOVERY_CLEANUP,
};

enum ath6kl_state {
	ATH6KL_STATE_OFF,
	ATH6KL_STATE_ON,
	ATH6KL_STATE_SUSPENDING,
	ATH6KL_STATE_RESUMING,
	ATH6KL_STATE_DEEPSLEEP,
	ATH6KL_STATE_CUTPOWER,
	ATH6KL_STATE_WOW,
	ATH6KL_STATE_RECOVERY,
};

/* Fw error recovery */
#define ATH6KL_HB_RESP_MISS_THRES	5

enum ath6kl_fw_err {
	ATH6KL_FW_ASSERT,
	ATH6KL_FW_HB_RESP_FAILURE,
	ATH6KL_FW_EP_FULL,
};

struct ath6kl_softc {
	device_t			sc_dev;
	struct ifnet			*sc_ifp;
	
	enum ath6kl_state state;
	unsigned int testmode;
	
	struct usb_device		*sc_udev;
	int				sc_iface_index;
	struct usb_xfer			*sc_xfer[ATH6KL_USB_N_XFERS];
	struct mtx			sc_mtx;	/* for usb xfer */
	struct ath6kl_bmi		sc_bmi;
	const struct ath6kl_hif_ops 	*sc_hif_ops;
	const struct ath6kl_htc_ops 	*sc_htc_ops;
	struct wmi 			*sc_wmi;
	int 				sc_tx_pending[ENDPOINT_MAX];
	int 				sc_total_tx_data_pend;
	struct htc_target 		*sc_htc_target;
	enum ath6kl_hif_type 		sc_hif_type;
	void 				*sc_hif_priv;	
	TAILQ_HEAD(,ath6kl_vif)		sc_vif_list;
	/* Lock to avoid race in vif_list entries among add/del/traverse */
	struct mtx 			sc_list_lock;
	uint8_t				sc_num_vif;
	unsigned int 			sc_vif_max;
	uint8_t				sc_max_norm_iface;
	uint8_t				sc_avail_idx_map;
	/*
	 * Protects at least amsdu_rx_buffer_queue, ath6kl_alloc_cookie()
	 * calls, tx_pending and total_tx_data_pend.
	 */
	struct mtx			sc_lock;
	
	struct sema                     sc_sem;
	
	uint8_t 			sc_lrssi_roam_threshold;
	struct ath6kl_version 		sc_version;
	uint32_t 			sc_target_type;
	uint8_t 			sc_tx_pwr;
	struct ath6kl_node_mapping 	sc_node_map[MAX_NODE_NUM];
	uint8_t 			sc_ibss_ps_enable;
	bool 				sc_ibss_if_active;
	uint8_t 			sc_node_num;
	uint8_t 			sc_next_ep_id;
	struct ath6kl_cookie 		*sc_cookie_list;
	uint32_t 			sc_cookie_count;
	enum htc_endpoint_id 		sc_ac2ep_map[WMM_NUM_AC];
	bool 				sc_ac_stream_active[WMM_NUM_AC];
	uint8_t 			sc_ac_stream_pri_map[WMM_NUM_AC];
	uint8_t 			sc_hiac_stream_active_pri;
	uint8_t 			sc_ep2ac_map[ENDPOINT_MAX];
	enum htc_endpoint_id 		sc_ctrl_ep;
	struct ath6kl_htc_credit_info 	sc_credit_state_info;
	uint32_t 			sc_connect_ctrl_flags;
	uint32_t 			sc_user_key_ctrl;
	uint8_t 			sc_usr_bss_filter;
	struct ath6kl_sta 		sc_sta_list[AP_MAX_NUM_STA];
	uint8_t 			sc_sta_list_index;
	struct ath6kl_req_key 		sc_ap_mode_bkey;
	ath6kl_buff_head	 	sc_mcastpsq;
	uint32_t 			sc_want_ch_switch;
	uint16_t 			sc_last_ch;
	
	/*
	 * FIXME: protects access to mcastpsq but is actually useless as
	 * all skbe_queue_*() functions provide serialisation themselves
	 */
	struct mtx			sc_mcastpsq_lock;
	uint8_t				sc_intra_bss;
	struct wmi_ap_mode_stat 	sc_ap_stats;
	uint8_t				sc_ap_country_code[3];
 	htc_packet_head 		sc_amsdu_rx_buffer_queue;
	uint8_t 			sc_rx_meta_ver;
	enum wlan_low_pwr_state 	sc_wlan_pwr_state;
	uint8_t				sc_mac_addr[IEEE80211_ADDR_LEN];
#define AR_MCAST_FILTER_MAC_ADDR_SIZE  4
	struct {
		void *rx_report;
		size_t rx_report_len;
	} 				sc_tm;

	struct ath6kl_hw {
		uint32_t id;
		const char *name;
		uint32_t dataset_patch_addr;
		uint32_t app_load_addr;
		uint32_t app_start_override_addr;
		uint32_t board_ext_data_addr;
		uint32_t reserved_ram_size;
		uint32_t board_addr;
		uint32_t refclk_hz;
		uint32_t uarttx_pin;
		uint32_t testscript_addr;
		enum wmi_phy_cap cap;

		uint32_t flags;

		struct ath6kl_hw_fw {
			const char *dir;
			const char *otp;
			const char *fw;
			const char *tcmd;
			const char *patch;
			const char *utf;
			const char *testscript;
		} fw;

		const char *fw_board;
		const char *fw_default_board;
	}				sc_hw;
	
	uint16_t			sc_conf_flags;
	uint16_t			sc_suspend_mode;
	uint16_t			sc_wow_suspend_mode;
	struct cv			sc_event_cv;
	struct mtx			sc_event_mtx;
	struct ath6kl_mbox_info 	sc_mbox_info;
	
	struct ath6kl_cookie 		sc_cookie_mem[MAX_COOKIE_NUM];
	unsigned long			sc_flag;

	const struct firmware		*sc_fw_board;
	
	uint8_t 			*sc_fw_otp;
	unsigned int 			sc_fw_otp_len;
	
	uint8_t				*sc_fw;	/* extracted from fw.bin */
	unsigned int			sc_fw_len;
	
	uint8_t 			*sc_fw_patch;
	unsigned int 			sc_fw_patch_len;
	
	uint8_t 			*sc_fw_testscript;
	unsigned int 			sc_fw_testscript_len;
	
	unsigned int			sc_fw_api;
	unsigned long			sc_fw_capabilities[ATH6KL_CAPABILITY_LEN];
	
	struct taskqueue		*sc_ath6kl_wq;

	char				sc_fw_version[32];

	int				sc_p2p;
	
	struct ath6kl_fw_recovery {
		struct task            work_task;
		void                    (*fn)(struct ath6kl_softc *);
		unsigned long err_reason;
		unsigned long hb_poll;
		struct callout hb_timer;
		uint32_t seq_num;
		bool hb_pending;
		uint8_t hb_misscnt;
		bool enable;
	} fw_recovery;

	uint32_t			sc_state;
	struct ath6kl_stat		sc_stat;
};

static inline uint32_t
ath6kl_get_hi_item_addr(struct ath6kl_softc *sc, uint32_t item_offset)
{
	uint32_t addr = 0;

	if (sc->sc_target_type == TARGET_TYPE_AR6003)
		addr = ATH6KL_AR6003_HI_START_ADDR + item_offset;
	else if (sc->sc_target_type == TARGET_TYPE_AR6004)
		addr = ATH6KL_AR6004_HI_START_ADDR + item_offset;

	return addr;
}

int ath6kl_core_create(struct ath6kl_softc *);
int ath6kl_core_init(struct ath6kl_softc *, enum ath6kl_htc_type);
void ath6kl_core_cleanup(struct ath6kl_softc *);
void ath6kl_core_destroy(struct ath6kl_softc *);
int ath6kl_init_hw_params(struct ath6kl_softc *);
int ath6kl_init_fetch_firmwares(struct ath6kl_softc *);
int ath6kl_init_hw_start(struct ath6kl_softc *);
int ath6kl_configure_target(struct ath6kl_softc *);

#endif /* CORE_H */
