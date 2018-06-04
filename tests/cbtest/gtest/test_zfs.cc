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

/*
 * Set of tests for testing zfs command. The tests here should not use library
 * or network APIs, but rather just execute zfs/zpool commands.
 */

#include <gtest/gtest.h>
#include <unistd.h>
#include <algorithm>

#include "gtest_utils.h"

using namespace GtestUtils;

TEST(RedundantMetadata, NoneValue) {
	std::string s;
	Zrepl zrepl;
	TestPool pool("redundantpool");
	std::string zvol_name = pool.getZvolName("vol1");

	zrepl.start();
	pool.create();
	pool.createZvol("vol1", "-o io.openebs:targetip=127.0.0.1");

	s = execCmd("zfs", std::string("get -Ho value redundant_metadata ") + zvol_name);
	// Trim white space at the end of string
	s.erase(std::find_if(s.rbegin(), s.rend(),
	    std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	EXPECT_STREQ(s.c_str(), "none");

	execCmd("zfs", std::string("set redundant_metadata=none ") + zvol_name);
}
