#!/bin/bash
set -x

# Copyright © 2020 The OpenEBS Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# NOTE: This script should be called from parent directory of cstor.
# If script is not able to checkout to relavant branch then it will checkout to master

cd libcstor || exit 1
# CASE1: If travis is triggered for develop branch PR then libcstor branch
#        should be point to master
# CASE2: If travis is triggered for branch creation/PR against release branch
#        then libcstor should point to corresponding branch
# CASE3: If travis is triggered for tag creation then libcstor should point to
#        release tag if doesn't exist it should point to release branch from
#        where travis is triggered

# Tag to release branch should be handled as follows:
# v2.0.0-RC1    => libcstor should be checkout to v2.0.x
# v2.1.0-xy-RC3 => libcstor should be checkout to v2.1.0-xy
# v2.1.0        => libcstor should be checkout to v2.1.x
if [ "${TRAVIS_BRANCH}" == "develop" ]; then
	git checkout master
elif [ -z "$TRAVIS_TAG" ]; then
	## If tag is empty then it is triggered for PR against release branch/branch creation
	git checkout "${TRAVIS_BRANCH}" || git checkout master
else
	## Try to checkout to release tag if not succeeded then checkout to release branch
        ## Since tag is created from release branch so it is safe to checkout to release branch
	git checkout "$TRAVIS_TAG"
	rc=$?
	if [ $rc -ne 0 ]; then
		# Examples:
                #  TRAVIS_TAG    ==> PREFIX
                #--------------------------
		# v2.0.0-RC1     ==> v2.0
		# v2.0.0-ee-RC1  ==> v2.0
                # v2.0.0         ==> v2.0
                # v2.0.0-ee      ==> v2.0
                # v1.12.1-RC1    ==> v1.12
                #--------------------------
		branch_name_prefix=$(echo "${TRAVIS_TAG}" | cut -f 1,2 -d '.')

		# Examples:
                # TRAVIS_TAG     ==> SUFFIX
                #--------------------------
		# v2.0.0-RC1     ==> Empty value
		# v2.0.0-ee-RC1  ==> ee-
                # v2.0.0         ==> v2.0.0
                # v2.0.0-ee      ==> ee
                # v1.12.1-RC1    ==> Empty value
                #--------------------------

		branch_name_suffix=$(echo "${TRAVIS_TAG}" | cut -d '-' -f 2- | sed 's/RC.*//')

		# NOTE: In above example if TRAVIS_TAG is v2.0.0 then prefix is also
		# same in such cases we no need to append branch name again with suffix
		if [ "${branch_name_suffix}" == "${TRAVIS_TAG}" ]; then
			branch_name=${branch_name_prefix}.x
		else
			branch_name=${branch_name_prefix}.x-${branch_name_suffix}
		fi
		## It will trim "-" if exists at end
		git checkout "${branch_name%-}"
	fi
fi
cd ../
