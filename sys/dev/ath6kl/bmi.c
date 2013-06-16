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
#include <dev/ath6kl/bmi.h>
#include <dev/ath6kl/target.h>
#include <dev/ath6kl/core.h>
#include <dev/ath6kl/hif.h>
#include <dev/ath6kl/hif-ops.h>

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
		return EACCES;
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

int
ath6kl_bmi_read(struct ath6kl_softc *sc, uint32_t addr, uint8_t *buf, uint32_t len)
{
	uint32_t cid = BMI_READ_MEMORY;
	int ret;
	uint32_t offset;
	uint32_t len_remain, rx_len;
	uint16_t size;

	if (sc->sc_bmi.done_sent) {
		ath6kl_err("bmi done sent already, cmd %d disallowed\n", cid);
		return EACCES;
	}

	size = sc->sc_bmi.max_data_size + sizeof(cid) + sizeof(addr) + sizeof(len);
	if (size > sc->sc_bmi.max_cmd_size) {
		printf("%s: size > sc->sc_bmi.max_cmd_size\n", __func__);
		return EINVAL;
	}
	memset(sc->sc_bmi.cmd_buf, 0, size);

	DPRINTF(sc, ATH6KL_DBG_BMI, "bmi read memory: device: addr: 0x%x, len: %d\n",
	   addr, len);

	len_remain = len;

	while (len_remain) {
		rx_len = (len_remain < sc->sc_bmi.max_data_size) ?
		    len_remain : sc->sc_bmi.max_data_size;
		offset = 0;
		memcpy(&(sc->sc_bmi.cmd_buf[offset]), &cid, sizeof(cid));
		offset += sizeof(cid);
		memcpy(&(sc->sc_bmi.cmd_buf[offset]), &addr, sizeof(addr));
		offset += sizeof(addr);
		memcpy(&(sc->sc_bmi.cmd_buf[offset]), &rx_len, sizeof(rx_len));
		offset += sizeof(len);

		ret = ath6kl_hif_bmi_write(sc, sc->sc_bmi.cmd_buf, offset);
		if (ret) {
			ath6kl_err("Unable to write to the device: %d\n",
				   ret);
			return ret;
		}
		ret = ath6kl_hif_bmi_read(sc, sc->sc_bmi.cmd_buf, rx_len);
		if (ret) {
			ath6kl_err("Unable to read from the device: %d\n",
				   ret);
			return ret;
		}
		memcpy(&buf[len - len_remain], sc->sc_bmi.cmd_buf, rx_len);
		len_remain -= rx_len; addr += rx_len;
	}

	return 0;
}

int
ath6kl_bmi_write(struct ath6kl_softc *sc, uint32_t addr, const uint8_t *buf,
    uint32_t len)
{
	uint32_t cid = BMI_WRITE_MEMORY;
	int ret;
	uint32_t offset;
	uint32_t len_remain, tx_len;
	const uint32_t header = sizeof(cid) + sizeof(addr) + sizeof(len);
	uint8_t aligned_buf[400];
	const uint8_t *src;

	if (sc->sc_bmi.done_sent) {
		ath6kl_err("bmi done sent already, cmd %d disallowed\n", cid);
		return EACCES;
	}

	if ((sc->sc_bmi.max_data_size + header) > sc->sc_bmi.max_cmd_size) {
		printf("(sc->sc_bmi.max_data_size + header) > sc->sc_bmi.max_cmd_size\n");
		return EINVAL;
	}

	if (sc->sc_bmi.max_data_size > sizeof(aligned_buf))
		return E2BIG;

	memset(sc->sc_bmi.cmd_buf, 0, sc->sc_bmi.max_data_size + header);

	DPRINTF(sc, ATH6KL_DBG_BMI, "bmi write memory: addr: 0x%x, len: %d\n", addr, len);

	len_remain = len;
	while (len_remain) {
		src = &buf[len - len_remain];

		if (len_remain < (sc->sc_bmi.max_data_size - header)) {
			if (len_remain & 3) {
				/* align it with 4 bytes */
				len_remain = len_remain +
					     (4 - (len_remain & 3));
				memcpy(aligned_buf, src, len_remain);
				src = aligned_buf;
			}
			tx_len = len_remain;
		} else {
			tx_len = (sc->sc_bmi.max_data_size - header);
		}

		offset = 0;
		memcpy(&(sc->sc_bmi.cmd_buf[offset]), &cid, sizeof(cid));
		offset += sizeof(cid);
		memcpy(&(sc->sc_bmi.cmd_buf[offset]), &addr, sizeof(addr));
		offset += sizeof(addr);
		memcpy(&(sc->sc_bmi.cmd_buf[offset]), &tx_len, sizeof(tx_len));
		offset += sizeof(tx_len);
		memcpy(&(sc->sc_bmi.cmd_buf[offset]), src, tx_len);
		offset += tx_len;

		ret = ath6kl_hif_bmi_write(sc, sc->sc_bmi.cmd_buf, offset);
		if (ret) {
			ath6kl_err("Unable to write to the device: %d\n",
				   ret);
			return ret;
		}
		len_remain -= tx_len; addr += tx_len;
	}

	return 0;
}

int ath6kl_bmi_reg_read(struct ath6kl_softc *sc, uint32_t addr, uint32_t *param)
{
	uint32_t cid = BMI_READ_SOC_REGISTER;
	int ret;
	uint32_t offset;
	uint16_t size;

	if (sc->sc_bmi.done_sent) {
		ath6kl_err("bmi done sent already, cmd %d disallowed\n", cid);
		return EACCES;
	}

	size = sizeof(cid) + sizeof(addr);
	if (size > sc->sc_bmi.max_cmd_size) {
		printf("%s: size > sc->sc_bmi.max_cmd_size\n", __func__);
		return EINVAL;
	}
	memset(sc->sc_bmi.cmd_buf, 0, size);

	DPRINTF(sc, ATH6KL_DBG_BMI, "bmi read SOC reg: addr: 0x%x\n", addr);

	offset = 0;
	memcpy(&(sc->sc_bmi.cmd_buf[offset]), &cid, sizeof(cid));
	offset += sizeof(cid);
	memcpy(&(sc->sc_bmi.cmd_buf[offset]), &addr, sizeof(addr));
	offset += sizeof(addr);

	ret = ath6kl_hif_bmi_write(sc, sc->sc_bmi.cmd_buf, offset);
	if (ret) {
		ath6kl_err("Unable to write to the device: %d\n", ret);
		return ret;
	}

	ret = ath6kl_hif_bmi_read(sc, sc->sc_bmi.cmd_buf, sizeof(*param));
	if (ret) {
		ath6kl_err("Unable to read from the device: %d\n", ret);
		return ret;
	}
	memcpy(param, sc->sc_bmi.cmd_buf, sizeof(*param));

	return 0;
}

int ath6kl_bmi_reg_write(struct ath6kl_softc *sc, uint32_t addr, uint32_t param)
{
	uint32_t cid = BMI_WRITE_SOC_REGISTER;
	int ret;
	uint32_t offset;
	uint16_t size;

	if (sc->sc_bmi.done_sent) {
		ath6kl_err("bmi done sent already, cmd %d disallowed\n", cid);
		return EACCES;
	}

	size = sizeof(cid) + sizeof(addr) + sizeof(param);
	if (size > sc->sc_bmi.max_cmd_size) {
		printf("%s: size > sc->sc_bmi.max_cmd_size\n", __func__);
		return EINVAL;
	}
	memset(sc->sc_bmi.cmd_buf, 0, size);

	DPRINTF(sc, ATH6KL_DBG_BMI, "bmi write SOC reg: addr: 0x%x, param: %d\n",
	    addr, param);

	offset = 0;
	memcpy(&(sc->sc_bmi.cmd_buf[offset]), &cid, sizeof(cid));
	offset += sizeof(cid);
	memcpy(&(sc->sc_bmi.cmd_buf[offset]), &addr, sizeof(addr));
	offset += sizeof(addr);
	memcpy(&(sc->sc_bmi.cmd_buf[offset]), &param, sizeof(param));
	offset += sizeof(param);

	ret = ath6kl_hif_bmi_write(sc, sc->sc_bmi.cmd_buf, offset);
	if (ret) {
		ath6kl_err("Unable to write to the device: %d\n", ret);
		return ret;
	}

	return 0;
}

int
ath6kl_bmi_lz_data(struct ath6kl_softc *sc, uint8_t *buf, uint32_t len)
{
	uint32_t cid = BMI_LZ_DATA;
	int ret;
	uint32_t offset;
	uint32_t len_remain, tx_len;
	const uint32_t header = sizeof(cid) + sizeof(len);
	uint16_t size;

	if (sc->sc_bmi.done_sent) {
		ath6kl_err("bmi done sent already, cmd %d disallowed\n", cid);
		return EACCES;
	}

	size = sc->sc_bmi.max_data_size + header;
	if (size > sc->sc_bmi.max_cmd_size) {
		printf("%s: size > sc->sc_bmi.max_cmd_size\n", __func__);
		return EINVAL;
	}
	memset(sc->sc_bmi.cmd_buf, 0, size);

	DPRINTF(sc, ATH6KL_DBG_BMI, "bmi send LZ data: len: %d)\n", len);

	len_remain = len;
	while (len_remain) {
		tx_len = (len_remain < (sc->sc_bmi.max_data_size - header)) ?
			  len_remain : (sc->sc_bmi.max_data_size - header);

		offset = 0;
		memcpy(&(sc->sc_bmi.cmd_buf[offset]), &cid, sizeof(cid));
		offset += sizeof(cid);
		memcpy(&(sc->sc_bmi.cmd_buf[offset]), &tx_len, sizeof(tx_len));
		offset += sizeof(tx_len);
		memcpy(&(sc->sc_bmi.cmd_buf[offset]), &buf[len - len_remain],
		       tx_len);
		offset += tx_len;

		ret = ath6kl_hif_bmi_write(sc, sc->sc_bmi.cmd_buf, offset);
		if (ret) {
			ath6kl_err("Unable to write to the device: %d\n",
				   ret);
			return ret;
		}

		len_remain -= tx_len;
	}

	return 0;
}

int
ath6kl_bmi_lz_stream_start(struct ath6kl_softc *sc, uint32_t addr)
{
	uint32_t cid = BMI_LZ_STREAM_START;
	int ret;
	uint32_t offset;
	uint16_t size;

	if (sc->sc_bmi.done_sent) {
		ath6kl_err("bmi done sent already, cmd %d disallowed\n", cid);
		return EACCES;
	}

	size = sizeof(cid) + sizeof(addr);
	if (size > sc->sc_bmi.max_cmd_size) {
		printf("%s: size > sc->sc_bmi.max_cmd_size\n", __func__);
		return EINVAL;
	}
	memset(sc->sc_bmi.cmd_buf, 0, size);

	DPRINTF(sc, ATH6KL_DBG_BMI, "bmi LZ stream start: addr: 0x%x)\n",
	    addr);

	offset = 0;
	memcpy(&(sc->sc_bmi.cmd_buf[offset]), &cid, sizeof(cid));
	offset += sizeof(cid);
	memcpy(&(sc->sc_bmi.cmd_buf[offset]), &addr, sizeof(addr));
	offset += sizeof(addr);

	ret = ath6kl_hif_bmi_write(sc, sc->sc_bmi.cmd_buf, offset);
	if (ret) {
		ath6kl_err("Unable to start LZ stream to the device: %d\n",
		   ret);
		return ret;
	}

	return 0;
}

int
ath6kl_bmi_fast_download(struct ath6kl_softc *sc, uint32_t addr, uint8_t *buf,
    uint32_t len)
{
	int ret;
	uint32_t last_word = 0;
	uint32_t last_word_offset = len & ~0x3;
	uint32_t unaligned_bytes = len & 0x3;

	ret = ath6kl_bmi_lz_stream_start(sc, addr);
	if (ret)
		return ret;
	if (unaligned_bytes) {
		/* copy the last word into a zero padded buffer */
		memcpy(&last_word, &buf[last_word_offset], unaligned_bytes);
	}

	ret = ath6kl_bmi_lz_data(sc, buf, last_word_offset);
	if (ret)
		return ret;

	if (unaligned_bytes)
		ret = ath6kl_bmi_lz_data(sc, (uint8_t *)&last_word, 4);

	if (!ret) {
		/* Close compressed stream and open a new (fake) one.
		 * This serves mainly to flush Target caches. */
		ret = ath6kl_bmi_lz_stream_start(sc, 0x00);
	}
	return ret;
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
		return EINVAL;

	/* cmd + addr + len + data_size */
	sc->sc_bmi.max_cmd_size = sc->sc_bmi.max_data_size +
	    (sizeof(uint32_t) * 3);

	sc->sc_bmi.cmd_buf = malloc(sc->sc_bmi.max_cmd_size, M_TEMP,
	    M_NOWAIT | M_ZERO);
	if (!sc->sc_bmi.cmd_buf)
		return ENOMEM;

	return 0;
}

void
ath6kl_bmi_cleanup(struct ath6kl_softc *sc)
{

	free(sc->sc_bmi.cmd_buf, M_TEMP);
	sc->sc_bmi.cmd_buf = NULL;
}
