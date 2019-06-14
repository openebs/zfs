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

/*
 * Copyright (c) 2018 CloudByte, Inc. All rights reserved.
 */

#include <gtest/gtest.h>
#include <unistd.h>

/* Avoid including conflicting C++ declarations for LE-BE conversions */
#define _SYS_BYTEORDER_H
#include <libuzfs.h>
#include <zrepl_mgmt.h>

#if DEBUG
inject_error_t inject_error;
#endif

TEST(uZFSServer, Setup) {
	kernel_init(FREAD);
	EXPECT_GT(kthread_nr, 0);
}

TEST(uZFSServer, ClientConnectNoServer) {
	EXPECT_NE(0, libuzfs_client_init(NULL));
}

TEST(uZFSServer, InitServer) {
	EXPECT_EQ(0, libuzfs_ioctl_init());
}

TEST(uZFSServer, ClientConnectServer) {
	EXPECT_EQ(0, libuzfs_client_init(NULL));
}
