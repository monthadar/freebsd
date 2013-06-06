/*	$OpenBSD: if_uathvar.h,v 1.3 2006/09/20 19:47:17 damien Exp $	*/
/*	$FreeBSD$	*/

/*-
 * Copyright (c) 2006
 *	Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2006 Sam Leffler, Errno Consulting
 * Copyright (c) 2008-2009 Weongyo Jeong <weongyo@freebsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
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
#ifndef IF_UATH6klVAR_H
#define IF_UATH6klVAR_H

/* USB stuff */
#define	ATH6KL_DATA_TIMEOUT	10000
#define	ATH6KL_CMD_TIMEOUT	1000

#define ATH6KL_MAX_CMDSZ         512

#define	ATH6KL_LOCK(sc)			mtx_lock(&(sc)->sc_mtx)
#define	ATH6KL_UNLOCK(sc)		mtx_unlock(&(sc)->sc_mtx)
#define	ATH6KL_ASSERT_LOCKED(sc)	mtx_assert(&(sc)->sc_mtx, MA_OWNED)

#endif /* IF_UATH6klVAR_H */
