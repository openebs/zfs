/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

#ifndef	_UZFS_IO_H
#define	_UZFS_IO_H

/*
 * writes metadata 'md' to zil records
 * is_rebuild: if IO is from target then it should be set to FALSE
 *		else it should be set to TRUE (in case of rebuild IO)
 */
extern int uzfs_write_data(void *zv, char *buf, uint64_t offset, uint64_t len,
    void *md, boolean_t is_rebuild);

/*
 * calculates length required to store metadata for the data that it reads, and
 * reads metadata and assigns to 'md' and its length to 'mdlen'
 */
extern int uzfs_read_data(void *zv, char *buf, uint64_t offset, uint64_t len,
    void *md, uint64_t *mdlen);

extern void uzfs_flush_data(void *zv);

/*
 * API to set/get rebuilding status
 *
 * If, rebuilding mode is set, then every normal write IO will be added to
 * condensed avl tree (incoming io tree). For IO with is_rebuild
 * flag set in uzfs_write_data, it will be checked with incoming_io_tree and
 * only non-overlapping part from IO will be written.
 */
extern void uzfs_zvol_set_rebuild_status(void *zv, int status);
extern int uzfs_zvol_get_rebuild_status(void *zv);

/*
 * API to set/get zvol status
 */
extern void uzfs_zvol_set_status(void *zv, int status);
extern int uzfs_zvol_get_status(void *zv);

#endif
