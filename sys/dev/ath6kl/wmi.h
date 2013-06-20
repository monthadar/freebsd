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
 * This file contains the definitions of the WMI protocol specified in the
 * Wireless Module Interface (WMI).  It includes definitions of all the
 * commands and events. Commands are messages from the host to the WM.
 * Events and Replies are messages from the WM to the host.
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
#ifndef WMI_H
#define WMI_H

#include <net80211/ieee80211.h>

#if 0 /* NOT YET */
#include "htc.h"
#endif

#define HTC_PROTOCOL_VERSION		0x0002
#define WMI_PROTOCOL_VERSION		0x0002
#define WMI_CONTROL_MSG_MAX_LEN		256
#define is_ethertype(type_or_len)	((type_or_len) >= 0x0600)

#define IP_ETHERTYPE		0x0800

#define WMI_IMPLICIT_PSTREAM	0xFF
#define WMI_MAX_THINSTREAM	15

#define SSID_IE_LEN_INDEX	13

/* Host side link management data structures */
#define SIG_QUALITY_THRESH_LVLS		6
#define SIG_QUALITY_UPPER_THRESH_LVLS	SIG_QUALITY_THRESH_LVLS
#define SIG_QUALITY_LOWER_THRESH_LVLS	SIG_QUALITY_THRESH_LVLS

#define A_BAND_24GHZ           0
#define A_BAND_5GHZ            1
#define ATH6KL_NUM_BANDS       2

/* in ms */
#define WMI_IMPLICIT_PSTREAM_INACTIVITY_INT 5000

static inline int32_t a_cpu_to_sle32(int32_t val)
{
	return htole32(val);
}

static inline int32_t int32_t_to_cpu(int32_t val)
{
	return le32toh(val);
}

static inline int16_t a_cpu_to_sle16(int16_t val)
{
	return htole16(val);
}

static inline int16_t int16_t_to_cpu(int16_t val)
{
	return le16toh(val);
}

struct sq_threshold_params {
	int16_t upper_threshold[SIG_QUALITY_UPPER_THRESH_LVLS];
	int16_t lower_threshold[SIG_QUALITY_LOWER_THRESH_LVLS];
	uint32_t upper_threshold_valid_count;
	uint32_t lower_threshold_valid_count;
	uint32_t polling_interval;
	uint8_t weight;
	uint8_t last_rssi;
	uint8_t last_rssi_poll_event;
};

//struct wmi_data_sync_bufs {
//	uint8_t traffic_class;
//	struct sk_buff *skb;
//};

/* WMM stream classes */
#define WMM_NUM_AC  4
#define WMM_AC_BE   0		/* best effort */
#define WMM_AC_BK   1		/* background */
#define WMM_AC_VI   2		/* video */
#define WMM_AC_VO   3		/* voice */

#define WMI_VOICE_USER_PRIORITY		0x7

//struct wmi {
//	uint16_t stream_exist_for_ac[WMM_NUM_AC];
//	uint8_t fat_pipe_exist;
//	struct ath6kl *parent_dev;
//	uint8_t pwr_mode;
//
//	/* protects fat_pipe_exist and stream_exist_for_ac */
//	spinlock_t lock;
//	enum htc_endpoint_id ep_id;
//	struct sq_threshold_params
//	    sq_threshld[SIGNAL_QUALITY_METRICS_NUM_MAX];
//	bool is_wmm_enabled;
//	uint8_t traffic_class;
//	bool is_probe_ssid;
//
//	uint8_t *last_mgmt_tx_frame;
//	size_t last_mgmt_tx_frame_len;
//	uint8_t saved_pwr_mode;
//};

struct host_app_area {
	uint32_t wmi_protocol_ver;
} __packed;

enum wmi_msg_type {
	DATA_MSGTYPE = 0x0,
	CNTL_MSGTYPE,
	SYNC_MSGTYPE,
	OPT_MSGTYPE,
};

/*
 * Macros for operating on WMI_DATA_HDR (info) field
 */

#define WMI_DATA_HDR_MSG_TYPE_MASK  0x03
#define WMI_DATA_HDR_MSG_TYPE_SHIFT 0
#define WMI_DATA_HDR_UP_MASK        0x07
#define WMI_DATA_HDR_UP_SHIFT       2

/* In AP mode, the same bit (b5) is used to indicate Power save state in
 * the Rx dir and More data bit state in the tx direction.
 */
#define WMI_DATA_HDR_PS_MASK        0x1
#define WMI_DATA_HDR_PS_SHIFT       5

#define WMI_DATA_HDR_MORE	0x20

enum wmi_data_hdr_data_type {
	WMI_DATA_HDR_DATA_TYPE_802_3 = 0,
	WMI_DATA_HDR_DATA_TYPE_802_11,

	/* used to be used for the PAL */
	WMI_DATA_HDR_DATA_TYPE_ACL,
};

/* Bitmap of data header flags */
enum wmi_data_hdr_flags {
	WMI_DATA_HDR_FLAGS_MORE = 0x1,
	WMI_DATA_HDR_FLAGS_EOSP = 0x2,
	WMI_DATA_HDR_FLAGS_UAPSD = 0x4,
};

#define WMI_DATA_HDR_DATA_TYPE_MASK     0x3
#define WMI_DATA_HDR_DATA_TYPE_SHIFT    6

/* Macros for operating on WMI_DATA_HDR (info2) field */
#define WMI_DATA_HDR_SEQNO_MASK     0xFFF
#define WMI_DATA_HDR_SEQNO_SHIFT    0

#define WMI_DATA_HDR_AMSDU_MASK     0x1
#define WMI_DATA_HDR_AMSDU_SHIFT    12

#define WMI_DATA_HDR_META_MASK      0x7
#define WMI_DATA_HDR_META_SHIFT     13

#define WMI_DATA_HDR_PAD_BEFORE_DATA_MASK               0xFF
#define WMI_DATA_HDR_PAD_BEFORE_DATA_SHIFT              0x8

/* Macros for operating on WMI_DATA_HDR (info3) field */
#define WMI_DATA_HDR_IF_IDX_MASK    0xF

#define WMI_DATA_HDR_TRIG	    0x10
#define WMI_DATA_HDR_EOSP	    0x10

struct wmi_data_hdr {
	int8_t rssi;

	/*
	 * usage of 'info' field(8-bit):
	 *
	 *  b1:b0       - WMI_MSG_TYPE
	 *  b4:b3:b2    - UP(tid)
	 *  b5          - Used in AP mode.
	 *  More-data in tx dir, PS in rx.
	 *  b7:b6       - Dot3 header(0),
	 *                Dot11 Header(1),
	 *                ACL data(2)
	 */
	uint8_t info;

	/*
	 * usage of 'info2' field(16-bit):
	 *
	 * b11:b0       - seq_no
	 * b12          - A-MSDU?
	 * b15:b13      - META_DATA_VERSION 0 - 7
	 */
	uint16_t info2;

	/*
	 * usage of info3, 16-bit:
	 * b3:b0	- Interface index
	 * b4		- uAPSD trigger in rx & EOSP in tx
	 * b15:b5	- Reserved
	 */
	uint16_t info3;
} __packed;

static inline uint8_t wmi_data_hdr_get_up(struct wmi_data_hdr *dhdr)
{
	return (dhdr->info >> WMI_DATA_HDR_UP_SHIFT) & WMI_DATA_HDR_UP_MASK;
}

static inline void wmi_data_hdr_set_up(struct wmi_data_hdr *dhdr,
				       uint8_t usr_pri)
{
	dhdr->info &= ~(WMI_DATA_HDR_UP_MASK << WMI_DATA_HDR_UP_SHIFT);
	dhdr->info |= usr_pri << WMI_DATA_HDR_UP_SHIFT;
}

static inline uint8_t wmi_data_hdr_get_dot11(struct wmi_data_hdr *dhdr)
{
	uint8_t data_type;

	data_type = (dhdr->info >> WMI_DATA_HDR_DATA_TYPE_SHIFT) &
				   WMI_DATA_HDR_DATA_TYPE_MASK;
	return (data_type == WMI_DATA_HDR_DATA_TYPE_802_11);
}

static inline uint16_t wmi_data_hdr_get_seqno(struct wmi_data_hdr *dhdr)
{
	return (le16toh(dhdr->info2) >> WMI_DATA_HDR_SEQNO_SHIFT) &
				WMI_DATA_HDR_SEQNO_MASK;
}

static inline uint8_t wmi_data_hdr_is_amsdu(struct wmi_data_hdr *dhdr)
{
	return (le16toh(dhdr->info2) >> WMI_DATA_HDR_AMSDU_SHIFT) &
			       WMI_DATA_HDR_AMSDU_MASK;
}

static inline uint8_t wmi_data_hdr_get_meta(struct wmi_data_hdr *dhdr)
{
	return (le16toh(dhdr->info2) >> WMI_DATA_HDR_META_SHIFT) &
			       WMI_DATA_HDR_META_MASK;
}

static inline uint8_t wmi_data_hdr_get_if_idx(struct wmi_data_hdr *dhdr)
{
	return le16toh(dhdr->info3) & WMI_DATA_HDR_IF_IDX_MASK;
}

/* Tx meta version definitions */
#define WMI_MAX_TX_META_SZ	12
#define WMI_META_VERSION_1	0x01
#define WMI_META_VERSION_2	0x02

/* Flag to signal to FW to calculate TCP checksum */
#define WMI_META_V2_FLAG_CSUM_OFFLOAD 0x01

struct wmi_tx_meta_v1 {
	/* packet ID to identify the tx request */
	uint8_t pkt_id;

	/* rate policy to be used for the tx of this frame */
	uint8_t rate_plcy_id;
} __packed;

struct wmi_tx_meta_v2 {
	/*
	 * Offset from start of the WMI header for csum calculation to
	 * begin.
	 */
	uint8_t csum_start;

	/* offset from start of WMI header where final csum goes */
	uint8_t csum_dest;

	/* no of bytes over which csum is calculated */
	uint8_t csum_flags;
} __packed;

struct wmi_rx_meta_v1 {
	uint8_t status;

	/* rate index mapped to rate at which this packet was received. */
	uint8_t rix;

	/* rssi of packet */
	uint8_t rssi;

	/* rf channel during packet reception */
	uint8_t channel;

	uint16_t flags;
} __packed;

struct wmi_rx_meta_v2 {
	uint16_t csum;

	/* bit 0 set -partial csum valid bit 1 set -test mode */
	uint8_t csum_flags;
} __packed;

#define WMI_CMD_HDR_IF_ID_MASK 0xF

/* Control Path */
struct wmi_cmd_hdr {
	uint16_t cmd_id;

	/* info1 - 16 bits
	 * b03:b00 - id
	 * b15:b04 - unused */
	uint16_t info1;

	/* for alignment */
	uint16_t reserved;
} __packed;

static inline uint8_t wmi_cmd_hdr_get_if_idx(struct wmi_cmd_hdr *chdr)
{
	return le16toh(chdr->info1) & WMI_CMD_HDR_IF_ID_MASK;
}

/* List of WMI commands */
enum wmi_cmd_id {
	WMI_CONNECT_CMDID = 0x0001,
	WMI_RECONNECT_CMDID,
	WMI_DISCONNECT_CMDID,
	WMI_SYNCHRONIZE_CMDID,
	WMI_CREATE_PSTREAM_CMDID,
	WMI_DELETE_PSTREAM_CMDID,
	/* WMI_START_SCAN_CMDID is to be deprecated. Use
	 * WMI_BEGIN_SCAN_CMDID instead. The new cmd supports P2P mgmt
	 * operations using station interface.
	 */
	WMI_START_SCAN_CMDID,
	WMI_SET_SCAN_PARAMS_CMDID,
	WMI_SET_BSS_FILTER_CMDID,
	WMI_SET_PROBED_SSID_CMDID,	/* 10 */
	WMI_SET_LISTEN_INT_CMDID,
	WMI_SET_BMISS_TIME_CMDID,
	WMI_SET_DISC_TIMEOUT_CMDID,
	WMI_GET_CHANNEL_LIST_CMDID,
	WMI_SET_BEACON_INT_CMDID,
	WMI_GET_STATISTICS_CMDID,
	WMI_SET_CHANNEL_PARAMS_CMDID,
	WMI_SET_POWER_MODE_CMDID,
	WMI_SET_IBSS_PM_CAPS_CMDID,
	WMI_SET_POWER_PARAMS_CMDID,	/* 20 */
	WMI_SET_POWERSAVE_TIMERS_POLICY_CMDID,
	WMI_ADD_CIPHER_KEY_CMDID,
	WMI_DELETE_CIPHER_KEY_CMDID,
	WMI_ADD_KRK_CMDID,
	WMI_DELETE_KRK_CMDID,
	WMI_SET_PMKID_CMDID,
	WMI_SET_TX_PWR_CMDID,
	WMI_GET_TX_PWR_CMDID,
	WMI_SET_ASSOC_INFO_CMDID,
	WMI_ADD_BAD_AP_CMDID,		/* 30 */
	WMI_DELETE_BAD_AP_CMDID,
	WMI_SET_TKIP_COUNTERMEASURES_CMDID,
	WMI_RSSI_THRESHOLD_PARAMS_CMDID,
	WMI_TARGET_ERROR_REPORT_BITMASK_CMDID,
	WMI_SET_ACCESS_PARAMS_CMDID,
	WMI_SET_RETRY_LIMITS_CMDID,
	WMI_SET_OPT_MODE_CMDID,
	WMI_OPT_TX_FRAME_CMDID,
	WMI_SET_VOICE_PKT_SIZE_CMDID,
	WMI_SET_MAX_SP_LEN_CMDID,	/* 40 */
	WMI_SET_ROAM_CTRL_CMDID,
	WMI_GET_ROAM_TBL_CMDID,
	WMI_GET_ROAM_DATA_CMDID,
	WMI_ENABLE_RM_CMDID,
	WMI_SET_MAX_OFFHOME_DURATION_CMDID,
	WMI_EXTENSION_CMDID,	/* Non-wireless extensions */
	WMI_SNR_THRESHOLD_PARAMS_CMDID,
	WMI_LQ_THRESHOLD_PARAMS_CMDID,
	WMI_SET_LPREAMBLE_CMDID,
	WMI_SET_RTS_CMDID,		/* 50 */
	WMI_CLR_RSSI_SNR_CMDID,
	WMI_SET_FIXRATES_CMDID,
	WMI_GET_FIXRATES_CMDID,
	WMI_SET_AUTH_MODE_CMDID,
	WMI_SET_REASSOC_MODE_CMDID,
	WMI_SET_WMM_CMDID,
	WMI_SET_WMM_TXOP_CMDID,
	WMI_TEST_CMDID,

	/* COEX AR6002 only */
	WMI_SET_BT_STATUS_CMDID,
	WMI_SET_BT_PARAMS_CMDID,	/* 60 */

	WMI_SET_KEEPALIVE_CMDID,
	WMI_GET_KEEPALIVE_CMDID,
	WMI_SET_APPIE_CMDID,
	WMI_GET_APPIE_CMDID,
	WMI_SET_WSC_STATUS_CMDID,

	/* Wake on Wireless */
	WMI_SET_HOST_SLEEP_MODE_CMDID,
	WMI_SET_WOW_MODE_CMDID,
	WMI_GET_WOW_LIST_CMDID,
	WMI_ADD_WOW_PATTERN_CMDID,
	WMI_DEL_WOW_PATTERN_CMDID,	/* 70 */

	WMI_SET_FRAMERATES_CMDID,
	WMI_SET_AP_PS_CMDID,
	WMI_SET_QOS_SUPP_CMDID,
	WMI_SET_IE_CMDID,

	/* WMI_THIN_RESERVED_... mark the start and end
	 * values for WMI_THIN_RESERVED command IDs. These
	 * command IDs can be found in wmi_thin.h */
	WMI_THIN_RESERVED_START = 0x8000,
	WMI_THIN_RESERVED_END = 0x8fff,

	/* Developer commands starts at 0xF000 */
	WMI_SET_BITRATE_CMDID = 0xF000,
	WMI_GET_BITRATE_CMDID,
	WMI_SET_WHALPARAM_CMDID,
	WMI_SET_MAC_ADDRESS_CMDID,
	WMI_SET_AKMP_PARAMS_CMDID,
	WMI_SET_PMKID_LIST_CMDID,
	WMI_GET_PMKID_LIST_CMDID,
	WMI_ABORT_SCAN_CMDID,
	WMI_SET_TARGET_EVENT_REPORT_CMDID,

	/* Unused */
	WMI_UNUSED1,
	WMI_UNUSED2,

	/* AP mode commands */
	WMI_AP_HIDDEN_SSID_CMDID,
	WMI_AP_SET_NUM_STA_CMDID,
	WMI_AP_ACL_POLICY_CMDID,
	WMI_AP_ACL_MAC_LIST_CMDID,
	WMI_AP_CONFIG_COMMIT_CMDID,
	WMI_AP_SET_MLME_CMDID,
	WMI_AP_SET_PVB_CMDID,
	WMI_AP_CONN_INACT_CMDID,
	WMI_AP_PROT_SCAN_TIME_CMDID,
	WMI_AP_SET_COUNTRY_CMDID,
	WMI_AP_SET_DTIM_CMDID,
	WMI_AP_MODE_STAT_CMDID,

	WMI_SET_IP_CMDID,
	WMI_SET_PARAMS_CMDID,
	WMI_SET_MCAST_FILTER_CMDID,
	WMI_DEL_MCAST_FILTER_CMDID,

	WMI_ALLOW_AGGR_CMDID,
	WMI_ADDBA_REQ_CMDID,
	WMI_DELBA_REQ_CMDID,
	WMI_SET_HT_CAP_CMDID,
	WMI_SET_HT_OP_CMDID,
	WMI_SET_TX_SELECT_RATES_CMDID,
	WMI_SET_TX_SGI_PARAM_CMDID,
	WMI_SET_RATE_POLICY_CMDID,

	WMI_HCI_CMD_CMDID,
	WMI_RX_FRAME_FORMAT_CMDID,
	WMI_SET_THIN_MODE_CMDID,
	WMI_SET_BT_WLAN_CONN_PRECEDENCE_CMDID,

	WMI_AP_SET_11BG_RATESET_CMDID,
	WMI_SET_PMK_CMDID,
	WMI_MCAST_FILTER_CMDID,

	/* COEX CMDID AR6003 */
	WMI_SET_BTCOEX_FE_ANT_CMDID,
	WMI_SET_BTCOEX_COLOCATED_BT_DEV_CMDID,
	WMI_SET_BTCOEX_SCO_CONFIG_CMDID,
	WMI_SET_BTCOEX_A2DP_CONFIG_CMDID,
	WMI_SET_BTCOEX_ACLCOEX_CONFIG_CMDID,
	WMI_SET_BTCOEX_BTINQUIRY_PAGE_CONFIG_CMDID,
	WMI_SET_BTCOEX_DEBUG_CMDID,
	WMI_SET_BTCOEX_BT_OPERATING_STATUS_CMDID,
	WMI_GET_BTCOEX_STATS_CMDID,
	WMI_GET_BTCOEX_CONFIG_CMDID,

	WMI_SET_DFS_ENABLE_CMDID,	/* F034 */
	WMI_SET_DFS_MINRSSITHRESH_CMDID,
	WMI_SET_DFS_MAXPULSEDUR_CMDID,
	WMI_DFS_RADAR_DETECTED_CMDID,

	/* P2P commands */
	WMI_P2P_SET_CONFIG_CMDID,	/* F038 */
	WMI_WPS_SET_CONFIG_CMDID,
	WMI_SET_REQ_DEV_ATTR_CMDID,
	WMI_P2P_FIND_CMDID,
	WMI_P2P_STOP_FIND_CMDID,
	WMI_P2P_GO_NEG_START_CMDID,
	WMI_P2P_LISTEN_CMDID,

	WMI_CONFIG_TX_MAC_RULES_CMDID,	/* F040 */
	WMI_SET_PROMISCUOUS_MODE_CMDID,
	WMI_RX_FRAME_FILTER_CMDID,
	WMI_SET_CHANNEL_CMDID,

	/* WAC commands */
	WMI_ENABLE_WAC_CMDID,
	WMI_WAC_SCAN_REPLY_CMDID,
	WMI_WAC_CTRL_REQ_CMDID,
	WMI_SET_DIV_PARAMS_CMDID,

	WMI_GET_PMK_CMDID,
	WMI_SET_PASSPHRASE_CMDID,
	WMI_SEND_ASSOC_RES_CMDID,
	WMI_SET_ASSOC_REQ_RELAY_CMDID,

	/* ACS command, consists of sub-commands */
	WMI_ACS_CTRL_CMDID,
	WMI_SET_EXCESS_TX_RETRY_THRES_CMDID,
	WMI_SET_TBD_TIME_CMDID, /*added for wmiconfig command for TBD */

	/* Pktlog cmds */
	WMI_PKTLOG_ENABLE_CMDID,
	WMI_PKTLOG_DISABLE_CMDID,

	/* More P2P Cmds */
	WMI_P2P_GO_NEG_REQ_RSP_CMDID,
	WMI_P2P_GRP_INIT_CMDID,
	WMI_P2P_GRP_FORMATION_DONE_CMDID,
	WMI_P2P_INVITE_CMDID,
	WMI_P2P_INVITE_REQ_RSP_CMDID,
	WMI_P2P_PROV_DISC_REQ_CMDID,
	WMI_P2P_SET_CMDID,

	WMI_GET_RFKILL_MODE_CMDID,
	WMI_SET_RFKILL_MODE_CMDID,
	WMI_AP_SET_APSD_CMDID,
	WMI_AP_APSD_BUFFERED_TRAFFIC_CMDID,

	WMI_P2P_SDPD_TX_CMDID, /* F05C */
	WMI_P2P_STOP_SDPD_CMDID,
	WMI_P2P_CANCEL_CMDID,
	/* Ultra low power store / recall commands */
	WMI_STORERECALL_CONFIGURE_CMDID,
	WMI_STORERECALL_RECALL_CMDID,
	WMI_STORERECALL_HOST_READY_CMDID,
	WMI_FORCE_TARGET_ASSERT_CMDID,

	WMI_SET_PROBED_SSID_EX_CMDID,
	WMI_SET_NETWORK_LIST_OFFLOAD_CMDID,
	WMI_SET_ARP_NS_OFFLOAD_CMDID,
	WMI_ADD_WOW_EXT_PATTERN_CMDID,
	WMI_GTK_OFFLOAD_OP_CMDID,
	WMI_REMAIN_ON_CHNL_CMDID,
	WMI_CANCEL_REMAIN_ON_CHNL_CMDID,
	/* WMI_SEND_ACTION_CMDID is to be deprecated. Use
	 * WMI_SEND_MGMT_CMDID instead. The new cmd supports P2P mgmt
	 * operations using station interface.
	 */
	WMI_SEND_ACTION_CMDID,
	WMI_PROBE_REQ_REPORT_CMDID,
	WMI_DISABLE_11B_RATES_CMDID,
	WMI_SEND_PROBE_RESPONSE_CMDID,
	WMI_GET_P2P_INFO_CMDID,
	WMI_AP_JOIN_BSS_CMDID,

	WMI_SMPS_ENABLE_CMDID,
	WMI_SMPS_CONFIG_CMDID,
	WMI_SET_RATECTRL_PARM_CMDID,
	/*  LPL specific commands*/
	WMI_LPL_FORCE_ENABLE_CMDID,
	WMI_LPL_SET_POLICY_CMDID,
	WMI_LPL_GET_POLICY_CMDID,
	WMI_LPL_GET_HWSTATE_CMDID,
	WMI_LPL_SET_PARAMS_CMDID,
	WMI_LPL_GET_PARAMS_CMDID,

	WMI_SET_BUNDLE_PARAM_CMDID,

	/*GreenTx specific commands*/

	WMI_GREENTX_PARAMS_CMDID,

	WMI_RTT_MEASREQ_CMDID,
	WMI_RTT_CAPREQ_CMDID,
	WMI_RTT_STATUSREQ_CMDID,

	/* WPS Commands */
	WMI_WPS_START_CMDID,
	WMI_GET_WPS_STATUS_CMDID,

	/* More P2P commands */
	WMI_SET_NOA_CMDID,
	WMI_GET_NOA_CMDID,
	WMI_SET_OPPPS_CMDID,
	WMI_GET_OPPPS_CMDID,
	WMI_ADD_PORT_CMDID,
	WMI_DEL_PORT_CMDID,

	/* 802.11w cmd */
	WMI_SET_RSN_CAP_CMDID,
	WMI_GET_RSN_CAP_CMDID,
	WMI_SET_IGTK_CMDID,

	WMI_RX_FILTER_COALESCE_FILTER_OP_CMDID,
	WMI_RX_FILTER_SET_FRAME_TEST_LIST_CMDID,

	WMI_SEND_MGMT_CMDID,
	WMI_BEGIN_SCAN_CMDID,

	WMI_SET_BLACK_LIST,
	WMI_SET_MCASTRATE,

	WMI_STA_BMISS_ENHANCE_CMDID,

	WMI_SET_REGDOMAIN_CMDID,

	WMI_SET_RSSI_FILTER_CMDID,

	WMI_SET_KEEP_ALIVE_EXT,

	WMI_VOICE_DETECTION_ENABLE_CMDID,

	WMI_SET_TXE_NOTIFY_CMDID,

	WMI_SET_RECOVERY_TEST_PARAMETER_CMDID, /*0xf094*/

	WMI_ENABLE_SCHED_SCAN_CMDID,
};

enum wmi_mgmt_frame_type {
	WMI_FRAME_BEACON = 0,
	WMI_FRAME_PROBE_REQ,
	WMI_FRAME_PROBE_RESP,
	WMI_FRAME_ASSOC_REQ,
	WMI_FRAME_ASSOC_RESP,
	WMI_NUM_MGMT_FRAME
};

enum wmi_ie_field_type {
	WMI_RSN_IE_CAPB	= 0x1,
	WMI_IE_FULL	= 0xFF,  /* indicats full IE */
};

/* WMI_CONNECT_CMDID  */
enum network_type {
	INFRA_NETWORK = 0x01,
	ADHOC_NETWORK = 0x02,
	ADHOC_CREATOR = 0x04,
	AP_NETWORK = 0x10,
};

enum network_subtype {
	SUBTYPE_NONE,
	SUBTYPE_BT,
	SUBTYPE_P2PDEV,
	SUBTYPE_P2PCLIENT,
	SUBTYPE_P2PGO,
};

enum dot11_auth_mode {
	OPEN_AUTH = 0x01,
	SHARED_AUTH = 0x02,

	/* different from IEEE_AUTH_MODE definitions */
	LEAP_AUTH = 0x04,
};

enum auth_mode {
	NONE_AUTH = 0x01,
	WPA_AUTH = 0x02,
	WPA2_AUTH = 0x04,
	WPA_PSK_AUTH = 0x08,
	WPA2_PSK_AUTH = 0x10,
	WPA_AUTH_CCKM = 0x20,
	WPA2_AUTH_CCKM = 0x40,
};

#define WMI_MAX_KEY_INDEX   3

#define WMI_MAX_KEY_LEN     32

/*
 * NB: these values are ordered carefully; there are lots of
 * of implications in any reordering.  In particular beware
 * that 4 is not used to avoid conflicting with IEEE80211_F_PRIVACY.
 */
#define ATH6KL_CIPHER_WEP            0
#define ATH6KL_CIPHER_TKIP           1
#define ATH6KL_CIPHER_AES_OCB        2
#define ATH6KL_CIPHER_AES_CCM        3
#define ATH6KL_CIPHER_CKIP           5
#define ATH6KL_CIPHER_CCKM_KRK       6
#define ATH6KL_CIPHER_NONE           7 /* pseudo value */

/*
 * 802.11 rate set.
 */
#define ATH6KL_RATE_MAXSIZE  15	/* max rates we'll handle */

#define ATH_OUI_TYPE            0x01
#define WPA_OUI_TYPE            0x01
#define WMM_PARAM_OUI_SUBTYPE   0x01
#define WMM_OUI_TYPE            0x02
#define WSC_OUT_TYPE            0x04

enum wmi_connect_ctrl_flags_bits {
	CONNECT_ASSOC_POLICY_USER = 0x0001,
	CONNECT_SEND_REASSOC = 0x0002,
	CONNECT_IGNORE_WPAx_GROUP_CIPHER = 0x0004,
	CONNECT_PROFILE_MATCH_DONE = 0x0008,
	CONNECT_IGNORE_AAC_BEACON = 0x0010,
	CONNECT_CSA_FOLLOW_BSS = 0x0020,
	CONNECT_DO_WPA_OFFLOAD = 0x0040,
	CONNECT_DO_NOT_DEAUTH = 0x0080,
	CONNECT_WPS_FLAG = 0x0100,
};

struct wmi_connect_cmd {
	uint8_t nw_type;
	uint8_t dot11_auth_mode;
	uint8_t auth_mode;
	uint8_t prwise_crypto_type;
	uint8_t prwise_crypto_len;
	uint8_t grp_crypto_type;
	uint8_t grp_crypto_len;
	uint8_t ssid_len;
	uint8_t ssid[IEEE80211_NWID_LEN];
	uint16_t ch;
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint32_t ctrl_flags;
	uint8_t nw_subtype;
} __packed;

/* WMI_RECONNECT_CMDID */
struct wmi_reconnect_cmd {
	/* channel hint */
	uint16_t channel;

	/* mandatory if set */
	uint8_t bssid[IEEE80211_ADDR_LEN];
} __packed;

/* WMI_ADD_CIPHER_KEY_CMDID */
enum key_usage {
	PAIRWISE_USAGE = 0x00,
	GROUP_USAGE = 0x01,

	/* default Tx Key - static WEP only */
	TX_USAGE = 0x02,
};

/*
 * Bit Flag
 * Bit 0 - Initialise TSC - default is Initialize
 */
#define KEY_OP_INIT_TSC     0x01
#define KEY_OP_INIT_RSC     0x02

/* default initialise the TSC & RSC */
#define KEY_OP_INIT_VAL     0x03
#define KEY_OP_VALID_MASK   0x03

/* XXX: FIXME, find correct definition or put it in correct place */
#define	WLAN_MAX_KEY_LEN	32

struct wmi_add_cipher_key_cmd {
	uint8_t key_index;
	uint8_t key_type;

	/* enum key_usage */
	uint8_t key_usage;

	uint8_t key_len;

	/* key replay sequence counter */
	uint8_t key_rsc[8];

	uint8_t key[WLAN_MAX_KEY_LEN];

	/* additional key control info */
	uint8_t key_op_ctrl;

	uint8_t key_mac_addr[IEEE80211_ADDR_LEN];
} __packed;

/* WMI_DELETE_CIPHER_KEY_CMDID */
struct wmi_delete_cipher_key_cmd {
	uint8_t key_index;
} __packed;

#define WMI_KRK_LEN     16

/* WMI_ADD_KRK_CMDID */
struct wmi_add_krk_cmd {
	uint8_t krk[WMI_KRK_LEN];
} __packed;

/* WMI_SETPMKID_CMDID */

#define WMI_PMKID_LEN 16

enum pmkid_enable_flg {
	PMKID_DISABLE = 0,
	PMKID_ENABLE = 1,
};

struct wmi_setpmkid_cmd {
	uint8_t bssid[IEEE80211_ADDR_LEN];

	/* enum pmkid_enable_flg */
	uint8_t enable;

	uint8_t pmkid[WMI_PMKID_LEN];
} __packed;

/* WMI_START_SCAN_CMD */
enum wmi_scan_type {
	WMI_LONG_SCAN = 0,
	WMI_SHORT_SCAN = 1,
};

struct wmi_supp_rates {
	uint8_t nrates;
	uint8_t rates[ATH6KL_RATE_MAXSIZE];
};

struct wmi_begin_scan_cmd {
	uint32_t force_fg_scan;

	/* for legacy cisco AP compatibility */
	uint32_t is_legacy;

	/* max duration in the home channel(msec) */
	uint32_t home_dwell_time;

	/* time interval between scans (msec) */
	uint32_t force_scan_intvl;

	/* no CCK rates */
	uint32_t no_cck;

	/* enum wmi_scan_type */
	uint8_t scan_type;

	/* Supported rates to advertise in the probe request frames */
	struct wmi_supp_rates supp_rates[ATH6KL_NUM_BANDS];

	/* how many channels follow */
	uint8_t num_ch;

	/* channels in Mhz */
	uint16_t ch_list[1];
} __packed;

/* wmi_start_scan_cmd is to be deprecated. Use
 * wmi_begin_scan_cmd instead. The new structure supports P2P mgmt
 * operations using station interface.
 */
struct wmi_start_scan_cmd {
	uint32_t force_fg_scan;

	/* for legacy cisco AP compatibility */
	uint32_t is_legacy;

	/* max duration in the home channel(msec) */
	uint32_t home_dwell_time;

	/* time interval between scans (msec) */
	uint32_t force_scan_intvl;

	/* enum wmi_scan_type */
	uint8_t scan_type;

	/* how many channels follow */
	uint8_t num_ch;

	/* channels in Mhz */
	uint16_t ch_list[1];
} __packed;

/*
 *  Warning: scan control flag value of 0xFF is used to disable
 *  all flags in WMI_SCAN_PARAMS_CMD. Do not add any more
 *  flags here
 */
enum wmi_scan_ctrl_flags_bits {

	/* set if can scan in the connect cmd */
	CONNECT_SCAN_CTRL_FLAGS = 0x01,

	/* set if scan for the SSID it is already connected to */
	SCAN_CONNECTED_CTRL_FLAGS = 0x02,

	/* set if enable active scan */
	ACTIVE_SCAN_CTRL_FLAGS = 0x04,

	/* set if enable roam scan when bmiss and lowrssi */
	ROAM_SCAN_CTRL_FLAGS = 0x08,

	/* set if follows customer BSSINFO reporting rule */
	REPORT_BSSINFO_CTRL_FLAGS = 0x10,

	/* if disabled, target doesn't scan after a disconnect event  */
	ENABLE_AUTO_CTRL_FLAGS = 0x20,

	/*
	 * Scan complete event with canceled status will be generated when
	 * a scan is prempted before it gets completed.
	 */
	ENABLE_SCAN_ABORT_EVENT = 0x40
};

struct wmi_scan_params_cmd {
	  /* sec */
	uint16_t fg_start_period;

	/* sec */
	uint16_t fg_end_period;

	/* sec */
	uint16_t bg_period;

	/* msec */
	uint16_t maxact_chdwell_time;

	/* msec */
	uint16_t pas_chdwell_time;

	  /* how many shorts scan for one long */
	uint8_t short_scan_ratio;

	uint8_t scan_ctrl_flags;

	/* msec */
	uint16_t minact_chdwell_time;

	/* max active scans per ssid */
	uint16_t maxact_scan_per_ssid;

	/* msecs */
	uint32_t max_dfsch_act_time;
} __packed;

/* WMI_ENABLE_SCHED_SCAN_CMDID */
struct wmi_enable_sched_scan_cmd {
	uint8_t enable;
} __packed;

/* WMI_SET_BSS_FILTER_CMDID */
enum wmi_bss_filter {
	/* no beacons forwarded */
	NONE_BSS_FILTER = 0x0,

	/* all beacons forwarded */
	ALL_BSS_FILTER,

	/* only beacons matching profile */
	PROFILE_FILTER,

	/* all but beacons matching profile */
	ALL_BUT_PROFILE_FILTER,

	/* only beacons matching current BSS */
	CURRENT_BSS_FILTER,

	/* all but beacons matching BSS */
	ALL_BUT_BSS_FILTER,

	/* beacons matching probed ssid */
	PROBED_SSID_FILTER,

	/* beacons matching matched ssid */
	MATCHED_SSID_FILTER,

	/* marker only */
	LAST_BSS_FILTER,
};

struct wmi_bss_filter_cmd {
	/* see, enum wmi_bss_filter */
	uint8_t bss_filter;

	/* for alignment */
	uint8_t reserved1;

	/* for alignment */
	uint16_t reserved2;

	uint32_t ie_mask;
} __packed;

/* WMI_SET_PROBED_SSID_CMDID */
#define MAX_PROBED_SSIDS   16

enum wmi_ssid_flag {
	/* disables entry */
	DISABLE_SSID_FLAG = 0,

	/* probes specified ssid */
	SPECIFIC_SSID_FLAG = 0x01,

	/* probes for any ssid */
	ANY_SSID_FLAG = 0x02,

	/* match for ssid */
	MATCH_SSID_FLAG = 0x08,
};

struct wmi_probed_ssid_cmd {
	/* 0 to MAX_PROBED_SSIDS - 1 */
	uint8_t entry_index;

	/* see, enum wmi_ssid_flg */
	uint8_t flag;

	uint8_t ssid_len;
	uint8_t ssid[IEEE80211_NWID_LEN];
} __packed;

/*
 * WMI_SET_LISTEN_INT_CMDID
 * The Listen interval is between 15 and 3000 TUs
 */
struct wmi_listen_int_cmd {
	uint16_t listen_intvl;
	uint16_t num_beacons;
} __packed;

/* WMI_SET_BMISS_TIME_CMDID */
struct wmi_bmiss_time_cmd {
	uint16_t bmiss_time;
	uint16_t num_beacons;
};

/* WMI_STA_ENHANCE_BMISS_CMDID */
struct wmi_sta_bmiss_enhance_cmd {
	uint8_t enable;
} __packed;

struct wmi_set_regdomain_cmd {
	uint8_t length;
	uint8_t iso_name[2];
} __packed;

/* WMI_SET_POWER_MODE_CMDID */
enum wmi_power_mode {
	REC_POWER = 0x01,
	MAX_PERF_POWER,
};

struct wmi_power_mode_cmd {
	/* see, enum wmi_power_mode */
	uint8_t pwr_mode;
} __packed;

/*
 * Policy to determnine whether power save failure event should be sent to
 * host during scanning
 */
enum power_save_fail_event_policy {
	SEND_POWER_SAVE_FAIL_EVENT_ALWAYS = 1,
	IGNORE_PS_FAIL_DURING_SCAN = 2,
};

struct wmi_power_params_cmd {
	/* msec */
	uint16_t idle_period;

	uint16_t pspoll_number;
	uint16_t dtim_policy;
	uint16_t tx_wakeup_policy;
	uint16_t num_tx_to_wakeup;
	uint16_t ps_fail_event_policy;
} __packed;

/*
 * Ratemask for below modes should be passed
 * to WMI_SET_TX_SELECT_RATES_CMDID.
 * AR6003 has 32 bit mask for each modes.
 * First 12 bits for legacy rates, 13 to 20
 * bits for HT 20 rates and 21 to 28 bits for
 * HT 40 rates
 */
enum wmi_mode_phy {
	WMI_RATES_MODE_11A = 0,
	WMI_RATES_MODE_11G,
	WMI_RATES_MODE_11B,
	WMI_RATES_MODE_11GONLY,
	WMI_RATES_MODE_11A_HT20,
	WMI_RATES_MODE_11G_HT20,
	WMI_RATES_MODE_11A_HT40,
	WMI_RATES_MODE_11G_HT40,
	WMI_RATES_MODE_MAX
};

/* WMI_SET_TX_SELECT_RATES_CMDID */
struct wmi_set_tx_select_rateint32_t_cmd {
	uint32_t ratemask[WMI_RATES_MODE_MAX];
} __packed;

/* WMI_SET_TX_SELECT_RATES_CMDID */
struct wmi_set_tx_select_rates64_cmd {
	uint64_t ratemask[WMI_RATES_MODE_MAX];
} __packed;

/* WMI_SET_DISC_TIMEOUT_CMDID */
struct wmi_disc_timeout_cmd {
	/* seconds */
	uint8_t discon_timeout;
} __packed;

enum dir_type {
	UPLINK_TRAFFIC = 0,
	DNLINK_TRAFFIC = 1,
	BIDIR_TRAFFIC = 2,
};

enum voiceps_cap_type {
	DISABLE_FOR_THIS_AC = 0,
	ENABLE_FOR_THIS_AC = 1,
	ENABLE_FOR_ALL_AC = 2,
};

enum traffic_type {
	TRAFFIC_TYPE_APERIODIC = 0,
	TRAFFIC_TYPE_PERIODIC = 1,
};

/* WMI_SYNCHRONIZE_CMDID */
struct wmi_sync_cmd {
	uint8_t data_sync_map;
} __packed;

/* WMI_CREATE_PSTREAM_CMDID */
struct wmi_create_pstream_cmd {
	/* msec */
	uint32_t min_service_int;

	/* msec */
	uint32_t max_service_int;

	/* msec */
	uint32_t inactivity_int;

	/* msec */
	uint32_t suspension_int;

	uint32_t service_start_time;

	/* in bps */
	uint32_t min_data_rate;

	/* in bps */
	uint32_t mean_data_rate;

	/* in bps */
	uint32_t peak_data_rate;

	uint32_t max_burst_size;
	uint32_t delay_bound;

	/* in bps */
	uint32_t min_phy_rate;

	uint32_t sba;
	uint32_t medium_time;

	/* in octects */
	uint16_t nominal_msdu;

	/* in octects */
	uint16_t max_msdu;

	uint8_t traffic_class;

	/* see, enum dir_type */
	uint8_t traffic_direc;

	uint8_t rx_queue_num;

	/* see, enum traffic_type */
	uint8_t traffic_type;

	/* see, enum voiceps_cap_type */
	uint8_t voice_psc_cap;
	uint8_t tsid;

	/* 802.1D user priority */
	uint8_t user_pri;

	/* nominal phy rate */
	uint8_t nominal_phy;
} __packed;

/* WMI_DELETE_PSTREAM_CMDID */
struct wmi_delete_pstream_cmd {
	uint8_t tx_queue_num;
	uint8_t rx_queue_num;
	uint8_t traffic_direc;
	uint8_t traffic_class;
	uint8_t tsid;
} __packed;

/* WMI_SET_CHANNEL_PARAMS_CMDID */
enum wmi_phy_mode {
	WMI_11A_MODE = 0x1,
	WMI_11G_MODE = 0x2,
	WMI_11AG_MODE = 0x3,
	WMI_11B_MODE = 0x4,
	WMI_11GONLY_MODE = 0x5,
	WMI_11G_HT20	= 0x6,
};

#define WMI_MAX_CHANNELS        32

/*
 *  WMI_RSSI_THRESHOLD_PARAMS_CMDID
 *  Setting the polltime to 0 would disable polling. Threshold values are
 *  in the ascending order, and should agree to:
 *  (lowThreshold_lowerVal < lowThreshold_upperVal < highThreshold_lowerVal
 *   < highThreshold_upperVal)
 */

struct wmi_rssi_threshold_params_cmd {
	/* polling time as a factor of LI */
	uint32_t poll_time;

	/* lowest of upper */
	int16_t thresh_above1_val;

	int16_t thresh_above2_val;
	int16_t thresh_above3_val;
	int16_t thresh_above4_val;
	int16_t thresh_above5_val;

	/* highest of upper */
	int16_t thresh_above6_val;

	/* lowest of bellow */
	int16_t thresh_below1_val;

	int16_t thresh_below2_val;
	int16_t thresh_below3_val;
	int16_t thresh_below4_val;
	int16_t thresh_below5_val;

	/* highest of bellow */
	int16_t thresh_below6_val;

	/* "alpha" */
	uint8_t weight;

	uint8_t reserved[3];
} __packed;

/*
 *  WMI_SNR_THRESHOLD_PARAMS_CMDID
 *  Setting the polltime to 0 would disable polling.
 */

struct wmi_snr_threshold_params_cmd {
	/* polling time as a factor of LI */
	uint32_t poll_time;

	/* "alpha" */
	uint8_t weight;

	/* lowest of uppper */
	uint8_t thresh_above1_val;

	uint8_t thresh_above2_val;
	uint8_t thresh_above3_val;

	/* highest of upper */
	uint8_t thresh_above4_val;

	/* lowest of bellow */
	uint8_t thresh_below1_val;

	uint8_t thresh_below2_val;
	uint8_t thresh_below3_val;

	/* highest of bellow */
	uint8_t thresh_below4_val;

	uint8_t reserved[3];
} __packed;

/* Don't report BSSs with signal (RSSI) below this threshold */
struct wmi_set_rssi_filter_cmd {
	int8_t rssi;
} __packed;

enum wmi_preamble_policy {
	WMI_IGNORE_BARKER_IN_ERP = 0,
	WMI_FOLLOW_BARKER_IN_ERP,
};

struct wmi_set_lpreamble_cmd {
	uint8_t status;
	uint8_t preamble_policy;
} __packed;

struct wmi_set_rts_cmd {
	uint16_t threshold;
} __packed;

/* WMI_SET_TX_PWR_CMDID */
struct wmi_set_tx_pwr_cmd {
	/* in dbM units */
	uint8_t dbM;
} __packed;

struct wmi_tx_pwr_reply {
	/* in dbM units */
	uint8_t dbM;
} __packed;

struct wmi_report_sleep_state_event {
	uint32_t sleep_state;
};

enum wmi_report_sleep_status {
	WMI_REPORT_SLEEP_STATUS_IS_DEEP_SLEEP = 0,
	WMI_REPORT_SLEEP_STATUS_IS_AWAKE
};
enum target_event_report_config {
	/* default */
	DISCONN_EVT_IN_RECONN = 0,

	NO_DISCONN_EVT_IN_RECONN
};

struct wmi_mcast_filter_cmd {
	uint8_t mcast_all_enable;
} __packed;

#define ATH6KL_MCAST_FILTER_MAC_ADDR_SIZE 6
struct wmi_mcast_filter_add_del_cmd {
	uint8_t mcast_mac[ATH6KL_MCAST_FILTER_MAC_ADDR_SIZE];
} __packed;

struct wmi_set_htcap_cmd {
	uint8_t band;
	uint8_t ht_enable;
	uint8_t ht40_supported;
	uint8_t ht20_sgi;
	uint8_t ht40_sgi;
	uint8_t intolerant_40mhz;
	uint8_t max_ampdu_len_exp;
} __packed;

/* Command Replies */

/* WMI_GET_CHANNEL_LIST_CMDID reply */
struct wmi_channel_list_reply {
	uint8_t reserved;

	/* number of channels in reply */
	uint8_t num_ch;

	/* channel in Mhz */
	uint16_t ch_list[1];
} __packed;

/* List of Events (target to host) */
enum wmi_event_id {
	WMI_READY_EVENTID = 0x1001,
	WMI_CONNECT_EVENTID,
	WMI_DISCONNECT_EVENTID,
	WMI_BSSINFO_EVENTID,
	WMI_CMDERROR_EVENTID,
	WMI_REGDOMAIN_EVENTID,
	WMI_PSTREAM_TIMEOUT_EVENTID,
	WMI_NEIGHBOR_REPORT_EVENTID,
	WMI_TKIP_MICERR_EVENTID,
	WMI_SCAN_COMPLETE_EVENTID,	/* 0x100a */
	WMI_REPORT_STATISTICS_EVENTID,
	WMI_RSSI_THRESHOLD_EVENTID,
	WMI_ERROR_REPORT_EVENTID,
	WMI_OPT_RX_FRAME_EVENTID,
	WMI_REPORT_ROAM_TBL_EVENTID,
	WMI_EXTENSION_EVENTID,
	WMI_CAC_EVENTID,
	WMI_SNR_THRESHOLD_EVENTID,
	WMI_LQ_THRESHOLD_EVENTID,
	WMI_TX_RETRY_ERR_EVENTID,	/* 0x1014 */
	WMI_REPORT_ROAM_DATA_EVENTID,
	WMI_TEST_EVENTID,
	WMI_APLIST_EVENTID,
	WMI_GET_WOW_LIST_EVENTID,
	WMI_GET_PMKID_LIST_EVENTID,
	WMI_CHANNEL_CHANGE_EVENTID,
	WMI_PEER_NODE_EVENTID,
	WMI_PSPOLL_EVENTID,
	WMI_DTIMEXPIRY_EVENTID,
	WMI_WLAN_VERSION_EVENTID,
	WMI_SET_PARAMS_REPLY_EVENTID,
	WMI_ADDBA_REQ_EVENTID,		/*0x1020 */
	WMI_ADDBA_RESP_EVENTID,
	WMI_DELBA_REQ_EVENTID,
	WMI_TX_COMPLETE_EVENTID,
	WMI_HCI_EVENT_EVENTID,
	WMI_ACL_DATA_EVENTID,
	WMI_REPORT_SLEEP_STATE_EVENTID,
	WMI_REPORT_BTCOEX_STATS_EVENTID,
	WMI_REPORT_BTCOEX_CONFIG_EVENTID,
	WMI_GET_PMK_EVENTID,

	/* DFS Events */
	WMI_DFS_HOST_ATTACH_EVENTID,
	WMI_DFS_HOST_INIT_EVENTID,
	WMI_DFS_RESET_DELAYLINES_EVENTID,
	WMI_DFS_RESET_RADARQ_EVENTID,
	WMI_DFS_RESET_AR_EVENTID,
	WMI_DFS_RESET_ARQ_EVENTID,
	WMI_DFS_SET_DUR_MULTIPLIER_EVENTID,
	WMI_DFS_SET_BANGRADAR_EVENTID,
	WMI_DFS_SET_DEBUGLEVEL_EVENTID,
	WMI_DFS_PHYERR_EVENTID,

	/* CCX Evants */
	WMI_CCX_RM_STATUS_EVENTID,

	/* P2P Events */
	WMI_P2P_GO_NEG_RESULT_EVENTID,

	WMI_WAC_SCAN_DONE_EVENTID,
	WMI_WAC_REPORT_BSS_EVENTID,
	WMI_WAC_START_WPS_EVENTID,
	WMI_WAC_CTRL_REQ_REPLY_EVENTID,

	WMI_REPORT_WMM_PARAMS_EVENTID,
	WMI_WAC_REJECT_WPS_EVENTID,

	/* More P2P Events */
	WMI_P2P_GO_NEG_REQ_EVENTID,
	WMI_P2P_INVITE_REQ_EVENTID,
	WMI_P2P_INVITE_RCVD_RESULT_EVENTID,
	WMI_P2P_INVITE_SENT_RESULT_EVENTID,
	WMI_P2P_PROV_DISC_RESP_EVENTID,
	WMI_P2P_PROV_DISC_REQ_EVENTID,

	/* RFKILL Events */
	WMI_RFKILL_STATE_CHANGE_EVENTID,
	WMI_RFKILL_GET_MODE_CMD_EVENTID,

	WMI_P2P_START_SDPD_EVENTID,
	WMI_P2P_SDPD_RX_EVENTID,

	WMI_SET_HOST_SLEEP_MODE_CMD_PROCESSED_EVENTID = 0x1047,

	WMI_THIN_RESERVED_START_EVENTID = 0x8000,
	/* Events in this range are reserved for thinmode */
	WMI_THIN_RESERVED_END_EVENTID = 0x8fff,

	WMI_SET_CHANNEL_EVENTID,
	WMI_ASSOC_REQ_EVENTID,

	/* Generic ACS event */
	WMI_ACS_EVENTID,
	WMI_STORERECALL_STORE_EVENTID,
	WMI_WOW_EXT_WAKE_EVENTID,
	WMI_GTK_OFFLOAD_STATUS_EVENTID,
	WMI_NETWORK_LIST_OFFLOAD_EVENTID,
	WMI_REMAIN_ON_CHNL_EVENTID,
	WMI_CANCEL_REMAIN_ON_CHNL_EVENTID,
	WMI_TX_STATUS_EVENTID,
	WMI_RX_PROBE_REQ_EVENTID,
	WMI_P2P_CAPABILITIES_EVENTID,
	WMI_RX_ACTION_EVENTID,
	WMI_P2P_INFO_EVENTID,

	/* WPS Events */
	WMI_WPS_GET_STATUS_EVENTID,
	WMI_WPS_PROFILE_EVENTID,

	/* more P2P events */
	WMI_NOA_INFO_EVENTID,
	WMI_OPPPS_INFO_EVENTID,
	WMI_PORT_STATUS_EVENTID,

	/* 802.11w */
	WMI_GET_RSN_CAP_EVENTID,

	WMI_TXE_NOTIFY_EVENTID,
};

struct wmi_ready_event_2 {
	uint32_t sw_version;
	uint32_t abi_version;
	uint8_t mac_addr[IEEE80211_ADDR_LEN];
	uint8_t phy_cap;
} __packed;

/* WMI_PHY_CAPABILITY */
enum wmi_phy_cap {
	WMI_11A_CAP = 0x01,
	WMI_11G_CAP = 0x02,
	WMI_11AG_CAP = 0x03,
	WMI_11AN_CAP = 0x04,
	WMI_11GN_CAP = 0x05,
	WMI_11AGN_CAP = 0x06,
};

/* Connect Event */
struct wmi_connect_event {
	union {
		struct {
			uint16_t ch;
			uint8_t bssid[IEEE80211_ADDR_LEN];
			uint16_t listen_intvl;
			uint16_t beacon_intvl;
			uint32_t nw_type;
		} sta;
		struct {
			uint8_t phymode;
			uint8_t aid;
			uint8_t mac_addr[IEEE80211_ADDR_LEN];
			uint8_t auth;
			uint8_t keymgmt;
			uint16_t cipher;
			uint8_t apsd_info;
			uint8_t unused[3];
		} ap_sta;
		struct {
			uint16_t ch;
			uint8_t bssid[IEEE80211_ADDR_LEN];
			uint8_t unused[8];
		} ap_bss;
	} u;
	uint8_t beacon_ie_len;
	uint8_t assoc_req_len;
	uint8_t assoc_resp_len;
	uint8_t assoc_info[1];
} __packed;

/* Disconnect Event */
enum wmi_disconnect_reason {
	NO_NETWORK_AVAIL = 0x01,

	/* bmiss */
	LOST_LINK = 0x02,

	DISCONNECT_CMD = 0x03,
	BSS_DISCONNECTED = 0x04,
	AUTH_FAILED = 0x05,
	ASSOC_FAILED = 0x06,
	NO_RESOURCES_AVAIL = 0x07,
	CSERV_DISCONNECT = 0x08,
	INVALID_PROFILE = 0x0a,
	DOT11H_CHANNEL_SWITCH = 0x0b,
	PROFILE_MISMATCH = 0x0c,
	CONNECTION_EVICTED = 0x0d,
	IBSS_MERGE = 0xe,
};

/* AP mode disconnect proto_reasons */
enum ap_disconnect_reason {
	WMI_AP_REASON_STA_LEFT		= 101,
	WMI_AP_REASON_FROM_HOST		= 102,
	WMI_AP_REASON_COMM_TIMEOUT	= 103,
	WMI_AP_REASON_MAX_STA		= 104,
	WMI_AP_REASON_ACL		= 105,
	WMI_AP_REASON_STA_ROAM		= 106,
	WMI_AP_REASON_DFS_CHANNEL	= 107,
};

#define ATH6KL_COUNTRY_RD_SHIFT        16

struct ath6kl_wmi_regdomain {
	uint32_t reg_code;
};

struct wmi_disconnect_event {
	/* reason code, see 802.11 spec. */
	uint16_t proto_reason_status;

	/* set if known */
	uint8_t bssid[IEEE80211_ADDR_LEN];

	/* see WMI_DISCONNECT_REASON */
	uint8_t disconn_reason;

	uint8_t assoc_resp_len;
	uint8_t assoc_info[1];
} __packed;

/*
 * BSS Info Event.
 * Mechanism used to inform host of the presence and characteristic of
 * wireless networks present.  Consists of bss info header followed by
 * the beacon or probe-response frame body.  The 802.11 header is no included.
 */
enum wmi_bi_ftype {
	BEACON_FTYPE = 0x1,
	PROBERESP_FTYPE,
	ACTION_MGMT_FTYPE,
	PROBEREQ_FTYPE,
};

#define DEF_LRSSI_SCAN_PERIOD		 5
#define DEF_LRSSI_ROAM_THRESHOLD	20
#define DEF_LRSSI_ROAM_FLOOR		60
#define DEF_SCAN_FOR_ROAM_INTVL		 2

enum wmi_roam_ctrl {
	WMI_FORCE_ROAM = 1,
	WMI_SET_ROAM_MODE,
	WMI_SET_HOST_BIAS,
	WMI_SET_LRSSI_SCAN_PARAMS,
};

enum wmi_roam_mode {
	WMI_DEFAULT_ROAM_MODE = 1, /* RSSI based roam */
	WMI_HOST_BIAS_ROAM_MODE = 2, /* Host bias based roam */
	WMI_LOCK_BSS_MODE = 3, /* Lock to the current BSS */
};

struct bss_bias {
	uint8_t bssid[IEEE80211_ADDR_LEN];
	int8_t bias;
} __packed;

struct bss_bias_info {
	uint8_t num_bss;
	struct bss_bias bss_bias[0];
} __packed;

struct low_rssi_scan_params {
	uint16_t lrssi_scan_period;
	int16_t lrssi_scan_threshold;
	int16_t lrssi_roam_threshold;
	uint8_t roam_rssi_floor;
	uint8_t reserved[1];
} __packed;

struct roam_ctrl_cmd {
	union {
		uint8_t bssid[IEEE80211_ADDR_LEN]; /* WMI_FORCE_ROAM */
		uint8_t roam_mode; /* WMI_SET_ROAM_MODE */
		struct bss_bias_info bss; /* WMI_SET_HOST_BIAS */
		struct low_rssi_scan_params params; /* WMI_SET_LRSSI_SCAN_PARAMS
						     */
	} __packed info;
	uint8_t roam_ctrl;
} __packed;

struct set_beacon_int_cmd {
	uint32_t beacon_intvl;
} __packed;

struct set_dtim_cmd {
	uint32_t dtim_period;
} __packed;

/* BSS INFO HDR version 2.0 */
struct wmi_bss_info_hdr2 {
	uint16_t ch; /* frequency in MHz */

	/* see, enum wmi_bi_ftype */
	uint8_t frame_type;

	uint8_t snr; /* note: rssi = snr - 95 dBm */
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint16_t ie_mask;
} __packed;

/* Command Error Event */
enum wmi_error_code {
	INVALID_PARAM = 0x01,
	ILLEGAL_STATE = 0x02,
	INTERNAL_ERROR = 0x03,
};

struct wmi_cmd_error_event {
	uint16_t cmd_id;
	uint8_t err_code;
} __packed;

struct wmi_pstream_timeout_event {
	uint8_t tx_queue_num;
	uint8_t rx_queue_num;
	uint8_t traffic_direc;
	uint8_t traffic_class;
} __packed;

/*
 * The WMI_NEIGHBOR_REPORT Event is generated by the target to inform
 * the host of BSS's it has found that matches the current profile.
 * It can be used by the host to cache PMKs and/to initiate pre-authentication
 * if the BSS supports it.  The first bssid is always the current associated
 * BSS.
 * The bssid and bssFlags information repeats according to the number
 * or APs reported.
 */
enum wmi_bss_flags {
	WMI_DEFAULT_BSS_FLAGS = 0x00,
	WMI_PREAUTH_CAPABLE_BSS = 0x01,
	WMI_PMKID_VALID_BSS = 0x02,
};

struct wmi_neighbor_info {
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint8_t bss_flags; /* enum wmi_bss_flags */
} __packed;

struct wmi_neighbor_report_event {
	uint8_t num_neighbors;
	struct wmi_neighbor_info neighbor[0];
} __packed;

/* TKIP MIC Error Event */
struct wmi_tkip_micerr_event {
	uint8_t key_id;
	uint8_t is_mcast;
} __packed;

enum wmi_scan_status {
	WMI_SCAN_STATUS_SUCCESS = 0,
};

/* WMI_SCAN_COMPLETE_EVENTID */
struct wmi_scan_complete_event {
	int32_t status;
} __packed;

#define MAX_OPT_DATA_LEN 1400

/*
 * Special frame receive Event.
 * Mechanism used to inform host of the receiption of the special frames.
 * Consists of special frame info header followed by special frame body.
 * The 802.11 header is not included.
 */
struct wmi_opt_rx_info_hdr {
	uint16_t ch;
	uint8_t frame_type;
	int8_t snr;
	uint8_t src_addr[IEEE80211_ADDR_LEN];
	uint8_t bssid[IEEE80211_ADDR_LEN];
} __packed;

/* Reporting statistic */
struct tx_stats {
	uint32_t pkt;
	uint32_t byte;
	uint32_t ucast_pkt;
	uint32_t ucast_byte;
	uint32_t mcast_pkt;
	uint32_t mcast_byte;
	uint32_t bcast_pkt;
	uint32_t bcast_byte;
	uint32_t rts_success_cnt;
	uint32_t pkt_per_ac[4];
	uint32_t err_per_ac[4];

	uint32_t err;
	uint32_t fail_cnt;
	uint32_t retry_cnt;
	uint32_t mult_retry_cnt;
	uint32_t rts_fail_cnt;
	int32_t ucast_rate;
} __packed;

struct rx_stats {
	uint32_t pkt;
	uint32_t byte;
	uint32_t ucast_pkt;
	uint32_t ucast_byte;
	uint32_t mcast_pkt;
	uint32_t mcast_byte;
	uint32_t bcast_pkt;
	uint32_t bcast_byte;
	uint32_t frgment_pkt;

	uint32_t err;
	uint32_t crc_err;
	uint32_t key_cache_miss;
	uint32_t decrypt_err;
	uint32_t dupl_frame;
	int32_t ucast_rate;
} __packed;

#define RATE_INDEX_WITHOUT_SGI_MASK     0x7f
#define RATE_INDEX_MSB     0x80

struct tkip_ccmp_stats {
	uint32_t tkip_local_mic_fail;
	uint32_t tkip_cnter_measures_invoked;
	uint32_t tkip_replays;
	uint32_t tkip_fmt_err;
	uint32_t ccmp_fmt_err;
	uint32_t ccmp_replays;
} __packed;

struct pm_stats {
	uint32_t pwr_save_failure_cnt;
	uint16_t stop_tx_failure_cnt;
	uint16_t atim_tx_failure_cnt;
	uint16_t atim_rx_failure_cnt;
	uint16_t bcn_rx_failure_cnt;
} __packed;

struct cserv_stats {
	uint32_t cs_bmiss_cnt;
	uint32_t cs_low_rssi_cnt;
	uint16_t cs_connect_cnt;
	uint16_t cs_discon_cnt;
	int16_t cs_ave_beacon_rssi;
	uint16_t cs_roam_count;
	int16_t cs_rssi;
	uint8_t cs_snr;
	uint8_t cs_ave_beacon_snr;
	uint8_t cs_last_roam_msec;
} __packed;

struct wlan_net_stats {
	struct tx_stats tx;
	struct rx_stats rx;
	struct tkip_ccmp_stats tkip_ccmp_stats;
} __packed;

struct arp_stats {
	uint32_t arp_received;
	uint32_t arp_matched;
	uint32_t arp_replied;
} __packed;

struct wlan_wow_stats {
	uint32_t wow_pkt_dropped;
	uint16_t wow_evt_discarded;
	uint8_t wow_host_pkt_wakeups;
	uint8_t wow_host_evt_wakeups;
} __packed;

struct wmi_target_stats {
	uint32_t lq_val;
	int32_t noise_floor_calib;
	struct pm_stats pm_stats;
	struct wlan_net_stats stats;
	struct wlan_wow_stats wow_stats;
	struct arp_stats arp_stats;
	struct cserv_stats cserv_stats;
} __packed;

/*
 * WMI_RSSI_THRESHOLD_EVENTID.
 * Indicate the RSSI events to host. Events are indicated when we breach a
 * thresold value.
 */
enum wmi_rssi_threshold_val {
	WMI_RSSI_THRESHOLD1_ABOVE = 0,
	WMI_RSSI_THRESHOLD2_ABOVE,
	WMI_RSSI_THRESHOLD3_ABOVE,
	WMI_RSSI_THRESHOLD4_ABOVE,
	WMI_RSSI_THRESHOLD5_ABOVE,
	WMI_RSSI_THRESHOLD6_ABOVE,
	WMI_RSSI_THRESHOLD1_BELOW,
	WMI_RSSI_THRESHOLD2_BELOW,
	WMI_RSSI_THRESHOLD3_BELOW,
	WMI_RSSI_THRESHOLD4_BELOW,
	WMI_RSSI_THRESHOLD5_BELOW,
	WMI_RSSI_THRESHOLD6_BELOW
};

struct wmi_rssi_threshold_event {
	int16_t rssi;
	uint8_t range;
} __packed;

enum wmi_snr_threshold_val {
	WMI_SNR_THRESHOLD1_ABOVE = 1,
	WMI_SNR_THRESHOLD1_BELOW,
	WMI_SNR_THRESHOLD2_ABOVE,
	WMI_SNR_THRESHOLD2_BELOW,
	WMI_SNR_THRESHOLD3_ABOVE,
	WMI_SNR_THRESHOLD3_BELOW,
	WMI_SNR_THRESHOLD4_ABOVE,
	WMI_SNR_THRESHOLD4_BELOW
};

struct wmi_snr_threshold_event {
	/* see, enum wmi_snr_threshold_val */
	uint8_t range;

	uint8_t snr;
} __packed;

/* WMI_REPORT_ROAM_TBL_EVENTID */
#define MAX_ROAM_TBL_CAND   5

struct wmi_bss_roam_info {
	int32_t roam_util;
	uint8_t bssid[IEEE80211_ADDR_LEN];
	int8_t rssi;
	int8_t rssidt;
	int8_t last_rssi;
	int8_t util;
	int8_t bias;

	/* for alignment */
	uint8_t reserved;
} __packed;

struct wmi_target_roam_tbl {
	uint16_t roam_mode;
	uint16_t num_entries;
	struct wmi_bss_roam_info info[];
} __packed;

/* WMI_CAC_EVENTID */
enum cac_indication {
	CAC_INDICATION_ADMISSION = 0x00,
	CAC_INDICATION_ADMISSION_RESP = 0x01,
	CAC_INDICATION_DELETE = 0x02,
	CAC_INDICATION_NO_RESP = 0x03,
};

#define WMM_TSPEC_IE_LEN   63

struct wmi_cac_event {
	uint8_t ac;
	uint8_t cac_indication;
	uint8_t status_code;
	uint8_t tspec_suggestion[WMM_TSPEC_IE_LEN];
} __packed;

/* WMI_APLIST_EVENTID */

enum aplist_ver {
	APLIST_VER1 = 1,
};

struct wmi_ap_info_v1 {
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint16_t channel;
} __packed;

union wmi_ap_info {
	struct wmi_ap_info_v1 ap_info_v1;
} __packed;

struct wmi_aplist_event {
	uint8_t ap_list_ver;
	uint8_t num_ap;
	union wmi_ap_info ap_list[1];
} __packed;

/* Developer Commands */

/*
 * WMI_SET_BITRATE_CMDID
 *
 * Get bit rate cmd uses same definition as set bit rate cmd
 */
enum wmi_bit_rate {
	RATE_AUTO = -1,
	RATE_1Mb = 0,
	RATE_2Mb = 1,
	RATE_5_5Mb = 2,
	RATE_11Mb = 3,
	RATE_6Mb = 4,
	RATE_9Mb = 5,
	RATE_12Mb = 6,
	RATE_18Mb = 7,
	RATE_24Mb = 8,
	RATE_36Mb = 9,
	RATE_48Mb = 10,
	RATE_54Mb = 11,
	RATE_MCS_0_20 = 12,
	RATE_MCS_1_20 = 13,
	RATE_MCS_2_20 = 14,
	RATE_MCS_3_20 = 15,
	RATE_MCS_4_20 = 16,
	RATE_MCS_5_20 = 17,
	RATE_MCS_6_20 = 18,
	RATE_MCS_7_20 = 19,
	RATE_MCS_0_40 = 20,
	RATE_MCS_1_40 = 21,
	RATE_MCS_2_40 = 22,
	RATE_MCS_3_40 = 23,
	RATE_MCS_4_40 = 24,
	RATE_MCS_5_40 = 25,
	RATE_MCS_6_40 = 26,
	RATE_MCS_7_40 = 27,
};

struct wmi_bit_rate_reply {
	/* see, enum wmi_bit_rate */
	int8_t rate_index;
} __packed;

/*
 * WMI_SET_FIXRATES_CMDID
 *
 * Get fix rates cmd uses same definition as set fix rates cmd
 */
struct wmi_fix_rates_reply {
	/* see wmi_bit_rate */
	uint32_t fix_rate_mask;
} __packed;

enum roam_data_type {
	/* get the roam time data */
	ROAM_DATA_TIME = 1,
};

struct wmi_target_roam_time {
	uint32_t disassoc_time;
	uint32_t no_txrx_time;
	uint32_t assoc_time;
	uint32_t allow_txrx_time;
	uint8_t disassoc_bssid[IEEE80211_ADDR_LEN];
	int8_t disassoc_bss_rssi;
	uint8_t assoc_bssid[IEEE80211_ADDR_LEN];
	int8_t assoc_bss_rssi;
} __packed;

enum wmi_txop_cfg {
	WMI_TXOP_DISABLED = 0,
	WMI_TXOP_ENABLED
};

struct wmi_set_wmm_txop_cmd {
	uint8_t txop_enable;
} __packed;

struct wmi_set_keepalive_cmd {
	uint8_t keep_alive_intvl;
} __packed;

struct wmi_get_keepalive_cmd {
	uint32_t configured;
	uint8_t keep_alive_intvl;
} __packed;

struct wmi_set_appie_cmd {
	uint8_t mgmt_frm_type; /* enum wmi_mgmt_frame_type */
	uint8_t ie_len;
	uint8_t ie_info[0];
} __packed;

struct wmi_set_ie_cmd {
	uint8_t ie_id;
	uint8_t ie_field;	/* enum wmi_ie_field_type */
	uint8_t ie_len;
	uint8_t reserved;
	uint8_t ie_info[0];
} __packed;

/* Notify the WSC registration status to the target */
#define WSC_REG_ACTIVE     1
#define WSC_REG_INACTIVE   0

#define WOW_MAX_FILTERS_PER_LIST 4
#define WOW_PATTERN_SIZE	 64

#define MAC_MAX_FILTERS_PER_LIST 4

struct wow_filter {
	uint8_t wow_valid_filter;
	uint8_t wow_filter_id;
	uint8_t wow_filter_size;
	uint8_t wow_filter_offset;
	uint8_t wow_filter_mask[WOW_PATTERN_SIZE];
	uint8_t wow_filter_pattern[WOW_PATTERN_SIZE];
} __packed;

#define MAX_IP_ADDRS  2

struct wmi_set_ip_cmd {
	/* IP in network byte order */
	uint32_t ips[MAX_IP_ADDRS];
} __packed;

enum ath6kl_wow_filters {
	WOW_FILTER_SSID			= 0x0001,
	WOW_FILTER_OPTION_MAGIC_PACKET  = 0x0002,
	WOW_FILTER_OPTION_EAP_REQ	= 0x0004,
	WOW_FILTER_OPTION_PATTERNS	= 0x0008,
	WOW_FILTER_OPTION_OFFLOAD_ARP	= 0x0010,
	WOW_FILTER_OPTION_OFFLOAD_NS	= 0x0020,
	WOW_FILTER_OPTION_OFFLOAD_GTK	= 0x0040,
	WOW_FILTER_OPTION_8021X_4WAYHS	= 0x0080,
	WOW_FILTER_OPTION_NLO_DISCVRY	= 0x0100,
	WOW_FILTER_OPTION_NWK_DISASSOC	= 0x0200,
	WOW_FILTER_OPTION_GTK_ERROR	= 0x0400,
	WOW_FILTER_OPTION_TEST_MODE	= 0x0800,
};

enum ath6kl_host_mode {
	ATH6KL_HOST_MODE_AWAKE,
	ATH6KL_HOST_MODE_ASLEEP,
};

struct wmi_set_host_sleep_mode_cmd {
	uint32_t awake;
	uint32_t asleep;
} __packed;

enum ath6kl_wow_mode {
	ATH6KL_WOW_MODE_DISABLE,
	ATH6KL_WOW_MODE_ENABLE,
};

struct wmi_set_wow_mode_cmd {
	uint32_t enable_wow;
	uint32_t filter;
	uint16_t host_req_delay;
} __packed;

struct wmi_add_wow_pattern_cmd {
	uint8_t filter_list_id;
	uint8_t filter_size;
	uint8_t filter_offset;
	uint8_t filter[0];
} __packed;

struct wmi_del_wow_pattern_cmd {
	uint16_t filter_list_id;
	uint16_t filter_id;
} __packed;

/* WMI_SET_TXE_NOTIFY_CMDID */
struct wmi_txe_notify_cmd {
	uint32_t rate;
	uint32_t pkts;
	uint32_t intvl;
} __packed;

/* WMI_TXE_NOTIFY_EVENTID */
struct wmi_txe_notify_event {
	uint32_t rate;
	uint32_t pkts;
} __packed;

/* WMI_SET_AKMP_PARAMS_CMD */

struct wmi_pmkid {
	uint8_t pmkid[WMI_PMKID_LEN];
} __packed;

/* WMI_GET_PMKID_LIST_CMD  Reply */
struct wmi_pmkid_list_reply {
	uint32_t num_pmkid;
	uint8_t bssid_list[IEEE80211_ADDR_LEN][1];
	struct wmi_pmkid pmkid_list[1];
} __packed;

/* WMI_ADDBA_REQ_EVENTID */
struct wmi_addba_req_event {
	uint8_t tid;
	uint8_t win_sz;
	uint16_t st_seq_no;

	/* f/w response for ADDBA Req; OK (0) or failure (!=0) */
	uint8_t status;
} __packed;

/* WMI_ADDBA_RESP_EVENTID */
struct wmi_addba_resp_event {
	uint8_t tid;

	/* OK (0), failure (!=0) */
	uint8_t status;

	/* three values: not supported(0), 3839, 8k */
	uint16_t amsdu_sz;
} __packed;

/* WMI_DELBA_EVENTID
 * f/w received a DELBA for peer and processed it.
 * Host is notified of this
 */
struct wmi_delba_event {
	uint8_t tid;
	uint8_t is_peer_initiator;
	uint16_t reason_code;
} __packed;

#define PEER_NODE_JOIN_EVENT		0x00
#define PEER_NODE_LEAVE_EVENT		0x01
#define PEER_FIRST_NODE_JOIN_EVENT	0x10
#define PEER_LAST_NODE_LEAVE_EVENT	0x11

struct wmi_peer_node_event {
	uint8_t event_code;
	uint8_t peer_mac_addr[IEEE80211_ADDR_LEN];
} __packed;

/* Transmit complete event data structure(s) */

/* version 1 of tx complete msg */
struct tx_complete_msg_v1 {
#define TX_COMPLETE_STATUS_SUCCESS 0
#define TX_COMPLETE_STATUS_RETRIES 1
#define TX_COMPLETE_STATUS_NOLINK  2
#define TX_COMPLETE_STATUS_TIMEOUT 3
#define TX_COMPLETE_STATUS_OTHER   4

	uint8_t status;

	/* packet ID to identify parent packet */
	uint8_t pkt_id;

	/* rate index on successful transmission */
	uint8_t rate_idx;

	/* number of ACK failures in tx attempt */
	uint8_t ack_failures;
} __packed;

struct wmi_tx_complete_event {
	/* no of tx comp msgs following this struct */
	uint8_t num_msg;

	/* length in bytes for each individual msg following this struct */
	uint8_t msg_len;

	/* version of tx complete msg data following this struct */
	uint8_t msg_type;

	/* individual messages follow this header */
	uint8_t reserved;
} __packed;

/*
 * ------- AP Mode definitions --------------
 */

/*
 * !!! Warning !!!
 * -Changing the following values needs compilation of both driver and firmware
 */
#define AP_MAX_NUM_STA          10

/* Spl. AID used to set DTIM flag in the beacons */
#define MCAST_AID               0xFF

#define DEF_AP_COUNTRY_CODE     "US "

/* Used with WMI_AP_SET_NUM_STA_CMDID */

/*
 * Used with WMI_AP_SET_MLME_CMDID
 */

/* MLME Commands */
#define WMI_AP_MLME_ASSOC       1   /* associate station */
#define WMI_AP_DISASSOC         2   /* disassociate station */
#define WMI_AP_DEAUTH           3   /* deauthenticate station */
#define WMI_AP_MLME_AUTHORIZE   4   /* authorize station */
#define WMI_AP_MLME_UNAUTHORIZE 5   /* unauthorize station */

struct wmi_ap_set_mlme_cmd {
	uint8_t mac[IEEE80211_ADDR_LEN];
	uint16_t reason;		/* 802.11 reason code */
	uint8_t cmd;			/* operation to perform (WMI_AP_*) */
} __packed;

struct wmi_ap_set_pvb_cmd {
	uint32_t flag;
	uint16_t rsvd;
	uint16_t aid;
} __packed;

struct wmi_rx_frame_format_cmd {
	/* version of meta data for rx packets <0 = default> (0-7 = valid) */
	uint8_t meta_ver;

	/*
	 * 1 == leave .11 header intact,
	 * 0 == replace .11 header with .3 <default>
	 */
	uint8_t dot11_hdr;

	/*
	 * 1 == defragmentation is performed by host,
	 * 0 == performed by target <default>
	 */
	uint8_t defrag_on_host;

	/* for alignment */
	uint8_t reserved[1];
} __packed;

struct wmi_ap_hidden_ssid_cmd {
	uint8_t hidden_ssid;
} __packed;

struct wmi_set_inact_period_cmd {
	uint32_t inact_period;
	uint8_t num_null_func;
} __packed;

/* AP mode events */
struct wmi_ap_set_apsd_cmd {
	uint8_t enable;
} __packed;

enum wmi_ap_apsd_buffered_traffic_flags {
	WMI_AP_APSD_NO_DELIVERY_FRAMES =  0x1,
};

struct wmi_ap_apsd_buffered_traffic_cmd {
	uint16_t aid;
	uint16_t bitmap;
	uint32_t flags;
} __packed;

/* WMI_PS_POLL_EVENT */
struct wmi_pspoll_event {
	uint16_t aid;
} __packed;

struct wmi_per_sta_stat {
	uint32_t tx_bytes;
	uint32_t tx_pkts;
	uint32_t tx_error;
	uint32_t tx_discard;
	uint32_t rx_bytes;
	uint32_t rx_pkts;
	uint32_t rx_error;
	uint32_t rx_discard;
	uint32_t aid;
} __packed;

struct wmi_ap_mode_stat {
	uint32_t action;
	struct wmi_per_sta_stat sta[AP_MAX_NUM_STA + 1];
} __packed;

/* End of AP mode definitions */

struct wmi_remain_on_chnl_cmd {
	uint32_t freq;
	uint32_t duration;
} __packed;

/* wmi_send_action_cmd is to be deprecated. Use
 * wmi_send_mgmt_cmd instead. The new structure supports P2P mgmt
 * operations using station interface.
 */
struct wmi_send_action_cmd {
	uint32_t id;
	uint32_t freq;
	uint32_t wait;
	uint16_t len;
	uint8_t data[0];
} __packed;

struct wmi_send_mgmt_cmd {
	uint32_t id;
	uint32_t freq;
	uint32_t wait;
	uint32_t no_cck;
	uint16_t len;
	uint8_t data[0];
} __packed;

struct wmi_tx_status_event {
	uint32_t id;
	uint8_t ack_status;
} __packed;

struct wmi_probe_req_report_cmd {
	uint8_t enable;
} __packed;

struct wmi_disable_11b_rates_cmd {
	uint8_t disable;
} __packed;

struct wmi_set_appie_extended_cmd {
	uint8_t role_id;
	uint8_t mgmt_frm_type;
	uint8_t ie_len;
	uint8_t ie_info[0];
} __packed;

struct wmi_remain_on_chnl_event {
	uint32_t freq;
	uint32_t duration;
} __packed;

struct wmi_cancel_remain_on_chnl_event {
	uint32_t freq;
	uint32_t duration;
	uint8_t status;
} __packed;

struct wmi_rx_action_event {
	uint32_t freq;
	uint16_t len;
	uint8_t data[0];
} __packed;

struct wmi_p2p_capabilities_event {
	uint16_t len;
	uint8_t data[0];
} __packed;

struct wmi_p2p_rx_probe_req_event {
	uint32_t freq;
	uint16_t len;
	uint8_t data[0];
} __packed;

#define P2P_FLAG_CAPABILITIES_REQ   (0x00000001)
#define P2P_FLAG_MACADDR_REQ        (0x00000002)
#define P2P_FLAG_HMODEL_REQ         (0x00000002)

struct wmi_get_p2p_info {
	uint32_t info_req_flags;
} __packed;

struct wmi_p2p_info_event {
	uint32_t info_req_flags;
	uint16_t len;
	uint8_t data[0];
} __packed;

struct wmi_p2p_capabilities {
	uint8_t go_power_save;
} __packed;

struct wmi_p2p_macaddr {
	uint8_t mac_addr[IEEE80211_ADDR_LEN];
} __packed;

struct wmi_p2p_hmodel {
	uint8_t p2p_model;
} __packed;

struct wmi_p2p_probe_response_cmd {
	uint32_t freq;
	uint8_t destination_addr[IEEE80211_ADDR_LEN];
	uint16_t len;
	uint8_t data[0];
} __packed;

/* Extended WMI (WMIX)
 *
 * Extended WMIX commands are encapsulated in a WMI message with
 * cmd=WMI_EXTENSION_CMD.
 *
 * Extended WMI commands are those that are needed during wireless
 * operation, but which are not really wireless commands.  This allows,
 * for instance, platform-specific commands.  Extended WMI commands are
 * embedded in a WMI command message with WMI_COMMAND_ID=WMI_EXTENSION_CMDID.
 * Extended WMI events are similarly embedded in a WMI event message with
 * WMI_EVENT_ID=WMI_EXTENSION_EVENTID.
 */
struct wmix_cmd_hdr {
	uint32_t cmd_id;
} __packed;

enum wmix_command_id {
	WMIX_DSETOPEN_REPLY_CMDID = 0x2001,
	WMIX_DSETDATA_REPLY_CMDID,
	WMIX_GPIO_OUTPUT_SET_CMDID,
	WMIX_GPIO_INPUT_GET_CMDID,
	WMIX_GPIO_REGISTER_SET_CMDID,
	WMIX_GPIO_REGISTER_GET_CMDID,
	WMIX_GPIO_INTR_ACK_CMDID,
	WMIX_HB_CHALLENGE_RESP_CMDID,
	WMIX_DBGLOG_CFG_MODULE_CMDID,
	WMIX_PROF_CFG_CMDID,	/* 0x200a */
	WMIX_PROF_ADDR_SET_CMDID,
	WMIX_PROF_START_CMDID,
	WMIX_PROF_STOP_CMDID,
	WMIX_PROF_COUNT_GET_CMDID,
};

enum wmix_event_id {
	WMIX_DSETOPENREQ_EVENTID = 0x3001,
	WMIX_DSETCLOSE_EVENTID,
	WMIX_DSETDATAREQ_EVENTID,
	WMIX_GPIO_INTR_EVENTID,
	WMIX_GPIO_DATA_EVENTID,
	WMIX_GPIO_ACK_EVENTID,
	WMIX_HB_CHALLENGE_RESP_EVENTID,
	WMIX_DBGLOG_EVENTID,
	WMIX_PROF_COUNT_EVENTID,
};

/*
 * ------Error Detection support-------
 */

/*
 * WMIX_HB_CHALLENGE_RESP_CMDID
 * Heartbeat Challenge Response command
 */
struct wmix_hb_challenge_resp_cmd {
	uint32_t cookie;
	uint32_t source;
} __packed;

struct ath6kl_wmix_dbglog_cfg_module_cmd {
	uint32_t valid;
	uint32_t config;
} __packed;

/* End of Extended WMI (WMIX) */

enum wmi_sync_flag {
	NO_SYNC_WMIFLAG = 0,

	/* transmit all queued data before cmd */
	SYNC_BEFORE_WMIFLAG,

	/* any new data waits until cmd execs */
	SYNC_AFTER_WMIFLAG,

	SYNC_BOTH_WMIFLAG,

	/* end marker */
	END_WMIFLAG
};

#if 0 /* NOT YET */
enum htc_endpoint_id ath6kl_wmi_get_control_ep(struct wmi *wmi);
void ath6kl_wmi_set_control_ep(struct wmi *wmi, enum htc_endpoint_id ep_id);
int ath6kl_wmi_dix_2_dot3(struct wmi *wmi, struct sk_buff *skb);
int ath6kl_wmi_data_hdr_add(struct wmi *wmi, struct sk_buff *skb,
			    uint8_t msg_type, uint32_t flags,
			    enum wmi_data_hdr_data_type data_type,
			    uint8_t meta_ver, void *tx_meta_info, uint8_t if_idx);

int ath6kl_wmi_dot11_hdr_remove(struct wmi *wmi, struct sk_buff *skb);
int ath6kl_wmi_dot3_2_dix(struct sk_buff *skb);
int ath6kl_wmi_implicit_create_pstream(struct wmi *wmi, uint8_t if_idx,
				       struct sk_buff *skb, uint32_t layer2_priority,
				       bool wmm_enabled, uint8_t *ac);

int ath6kl_wmi_control_rx(struct wmi *wmi, struct sk_buff *skb);

int ath6kl_wmi_cmd_send(struct wmi *wmi, uint8_t if_idx, struct sk_buff *skb,
			enum wmi_cmd_id cmd_id, enum wmi_sync_flag sync_flag);

int ath6kl_wmi_connect_cmd(struct wmi *wmi, uint8_t if_idx,
			   enum network_type nw_type,
			   enum dot11_auth_mode dot11_auth_mode,
			   enum auth_mode auth_mode,
			   enum crypto_type pairwise_crypto,
			   uint8_t pairwise_crypto_len,
			   enum crypto_type group_crypto,
			   uint8_t group_crypto_len, int ssid_len, uint8_t *ssid,
			   uint8_t *bssid, uint16_t channel, uint32_t ctrl_flags,
			   uint8_t nw_subtype);

int ath6kl_wmi_reconnect_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t *bssid,
			     uint16_t channel);
int ath6kl_wmi_disconnect_cmd(struct wmi *wmi, uint8_t if_idx);

int ath6kl_wmi_beginscan_cmd(struct wmi *wmi, uint8_t if_idx,
			     enum wmi_scan_type scan_type,
			     uint32_t force_fgscan, uint32_t is_legacy,
			     uint32_t home_dwell_time, uint32_t force_scan_interval,
			     int8_t num_chan, uint16_t *ch_list, uint32_t no_cck,
			     uint32_t *rates);
int ath6kl_wmi_enable_sched_scan_cmd(struct wmi *wmi, uint8_t if_idx, bool enable);

int ath6kl_wmi_scanparams_cmd(struct wmi *wmi, uint8_t if_idx, uint16_t fg_start_sec,
			      uint16_t fg_end_sec, uint16_t bg_sec,
			      uint16_t minact_chdw_msec, uint16_t maxact_chdw_msec,
			      uint16_t pas_chdw_msec, uint8_t short_scan_ratio,
			      uint8_t scan_ctrl_flag, uint32_t max_dfsch_act_time,
			      uint16_t maxact_scan_per_ssid);
int ath6kl_wmi_bssfilter_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t filter,
			     uint32_t ie_mask);
int ath6kl_wmi_probedssid_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t index, uint8_t flag,
			      uint8_t ssid_len, uint8_t *ssid);
int ath6kl_wmi_listeninterval_cmd(struct wmi *wmi, uint8_t if_idx,
				  uint16_t listen_interval,
				  uint16_t listen_beacons);
int ath6kl_wmi_bmisstime_cmd(struct wmi *wmi, uint8_t if_idx,
			     uint16_t bmiss_time, uint16_t num_beacons);
int ath6kl_wmi_powermode_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t pwr_mode);
int ath6kl_wmi_pmparams_cmd(struct wmi *wmi, uint8_t if_idx, uint16_t idle_period,
			    uint16_t ps_poll_num, uint16_t dtim_policy,
			    uint16_t tx_wakup_policy, uint16_t num_tx_to_wakeup,
			    uint16_t ps_fail_event_policy);
int ath6kl_wmi_create_pstream_cmd(struct wmi *wmi, uint8_t if_idx,
				  struct wmi_create_pstream_cmd *pstream);
int ath6kl_wmi_delete_pstream_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t traffic_class,
				  uint8_t tsid);
int ath6kl_wmi_disctimeout_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t timeout);

int ath6kl_wmi_set_rts_cmd(struct wmi *wmi, uint16_t threshold);
int ath6kl_wmi_set_lpreamble_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t status,
				 uint8_t preamble_policy);

int ath6kl_wmi_get_challenge_resp_cmd(struct wmi *wmi, uint32_t cookie, uint32_t source);
int ath6kl_wmi_config_debug_module_cmd(struct wmi *wmi, uint32_t valid, uint32_t config);

int ath6kl_wmi_get_stats_cmd(struct wmi *wmi, uint8_t if_idx);
int ath6kl_wmi_addkey_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t key_index,
			  enum crypto_type key_type,
			  uint8_t key_usage, uint8_t key_len,
			  uint8_t *key_rsc, unsigned int key_rsc_len,
			  uint8_t *key_material,
			  uint8_t key_op_ctrl, uint8_t *mac_addr,
			  enum wmi_sync_flag sync_flag);
int ath6kl_wmi_add_krk_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t *krk);
int ath6kl_wmi_deletekey_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t key_index);
int ath6kl_wmi_setpmkid_cmd(struct wmi *wmi, uint8_t if_idx, const uint8_t *bssid,
			    const uint8_t *pmkid, bool set);
int ath6kl_wmi_set_tx_pwr_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t dbM);
int ath6kl_wmi_get_tx_pwr_cmd(struct wmi *wmi, uint8_t if_idx);
int ath6kl_wmi_get_roam_tbl_cmd(struct wmi *wmi);

int ath6kl_wmi_set_wmm_txop(struct wmi *wmi, uint8_t if_idx, enum wmi_txop_cfg cfg);
int ath6kl_wmi_set_keepalive_cmd(struct wmi *wmi, uint8_t if_idx,
				 uint8_t keep_alive_intvl);
int ath6kl_wmi_set_htcap_cmd(struct wmi *wmi, uint8_t if_idx,
			     enum ieee80211_band band,
			     struct ath6kl_htcap *htcap);
int ath6kl_wmi_test_cmd(struct wmi *wmi, void *buf, size_t len);

int32_t ath6kl_wmi_get_rate(int8_t rate_index);

int ath6kl_wmi_set_ip_cmd(struct wmi *wmi, uint8_t if_idx,
			  uint32_t ips0, uint32_t ips1);
int ath6kl_wmi_set_host_sleep_mode_cmd(struct wmi *wmi, uint8_t if_idx,
				       enum ath6kl_host_mode host_mode);
int ath6kl_wmi_set_bitrate_mask(struct wmi *wmi, uint8_t if_idx,
				const struct cfg80211_bitrate_mask *mask);
int ath6kl_wmi_set_wow_mode_cmd(struct wmi *wmi, uint8_t if_idx,
				enum ath6kl_wow_mode wow_mode,
				uint32_t filter, uint16_t host_req_delay);
int ath6kl_wmi_add_wow_pattern_cmd(struct wmi *wmi, uint8_t if_idx,
				   uint8_t list_id, uint8_t filter_size,
				   uint8_t filter_offset, const uint8_t *filter,
				   const uint8_t *mask);
int ath6kl_wmi_del_wow_pattern_cmd(struct wmi *wmi, uint8_t if_idx,
				   uint16_t list_id, uint16_t filter_id);
int ath6kl_wmi_set_rssi_filter_cmd(struct wmi *wmi, uint8_t if_idx, int8_t rssi);
int ath6kl_wmi_set_roam_lrssi_cmd(struct wmi *wmi, uint8_t lrssi);
int ath6kl_wmi_ap_set_dtim_cmd(struct wmi *wmi, uint8_t if_idx, uint32_t dtim_period);
int ath6kl_wmi_ap_set_beacon_intvl_cmd(struct wmi *wmi, uint8_t if_idx,
				       uint32_t beacon_interval);
int ath6kl_wmi_force_roam_cmd(struct wmi *wmi, const uint8_t *bssid);
int ath6kl_wmi_set_roam_mode_cmd(struct wmi *wmi, enum wmi_roam_mode mode);
int ath6kl_wmi_mcast_filter_cmd(struct wmi *wmi, uint8_t if_idx, bool mc_all_on);
int ath6kl_wmi_add_del_mcast_filter_cmd(struct wmi *wmi, uint8_t if_idx,
					uint8_t *filter, bool add_filter);
int ath6kl_wmi_sta_bmiss_enhance_cmd(struct wmi *wmi, uint8_t if_idx, bool enable);
int ath6kl_wmi_set_txe_notify(struct wmi *wmi, uint8_t idx,
			      uint32_t rate, uint32_t pkts, uint32_t intvl);
int ath6kl_wmi_set_regdomain_cmd(struct wmi *wmi, const char *alpha2);

/* AP mode uAPSD */
int ath6kl_wmi_ap_set_apsd(struct wmi *wmi, uint8_t if_idx, uint8_t enable);

int ath6kl_wmi_set_apsd_bfrd_traf(struct wmi *wmi,
						uint8_t if_idx, uint16_t aid,
						uint16_t bitmap, uint32_t flags);

uint8_t ath6kl_wmi_get_traffic_class(uint8_t user_priority);

uint8_t ath6kl_wmi_determine_user_priority(uint8_t *pkt, uint32_t layer2_pri);
/* AP mode */
int ath6kl_wmi_ap_hidden_ssid(struct wmi *wmi, uint8_t if_idx, bool enable);
int ath6kl_wmi_ap_profile_commit(struct wmi *wmip, uint8_t if_idx,
				 struct wmi_connect_cmd *p);

int ath6kl_wmi_ap_set_mlme(struct wmi *wmip, uint8_t if_idx, uint8_t cmd,
			   const uint8_t *mac, uint16_t reason);

int ath6kl_wmi_set_pvb_cmd(struct wmi *wmi, uint8_t if_idx, uint16_t aid, bool flag);

int ath6kl_wmi_set_rx_frame_format_cmd(struct wmi *wmi, uint8_t if_idx,
				       uint8_t rx_meta_version,
				       bool rx_dot11_hdr, bool defrag_on_host);

int ath6kl_wmi_set_appie_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t mgmt_frm_type,
			     const uint8_t *ie, uint8_t ie_len);

int ath6kl_wmi_set_ie_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t ie_id, uint8_t ie_field,
			  const uint8_t *ie_info, uint8_t ie_len);

/* P2P */
int ath6kl_wmi_disable_11b_rates_cmd(struct wmi *wmi, bool disable);

int ath6kl_wmi_remain_on_chnl_cmd(struct wmi *wmi, uint8_t if_idx, uint32_t freq,
				  uint32_t dur);

int ath6kl_wmi_send_mgmt_cmd(struct wmi *wmi, uint8_t if_idx, uint32_t id, uint32_t freq,
			       uint32_t wait, const uint8_t *data, uint16_t data_len,
			       uint32_t no_cck);

int ath6kl_wmi_send_probe_response_cmd(struct wmi *wmi, uint8_t if_idx, uint32_t freq,
				       const uint8_t *dst, const uint8_t *data,
				       uint16_t data_len);

int ath6kl_wmi_probe_report_req_cmd(struct wmi *wmi, uint8_t if_idx, bool enable);

int ath6kl_wmi_info_req_cmd(struct wmi *wmi, uint8_t if_idx, uint32_t info_req_flags);

int ath6kl_wmi_cancel_remain_on_chnl_cmd(struct wmi *wmi, uint8_t if_idx);

int ath6kl_wmi_set_appie_cmd(struct wmi *wmi, uint8_t if_idx, uint8_t mgmt_frm_type,
			     const uint8_t *ie, uint8_t ie_len);

int ath6kl_wmi_set_inact_period(struct wmi *wmi, uint8_t if_idx, int inact_timeout);

void ath6kl_wmi_sscan_timer(unsigned long ptr);

int ath6kl_wmi_get_challenge_resp_cmd(struct wmi *wmi, uint32_t cookie, uint32_t source);

struct ath6kl_vif *ath6kl_get_vif_by_index(struct ath6kl *ar, uint8_t if_idx);
void *ath6kl_wmi_init(struct ath6kl *devt);
void ath6kl_wmi_shutdown(struct wmi *wmi);
void ath6kl_wmi_reset(struct wmi *wmi);
#endif
#endif /* WMI_H */
