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
 * Copyright (c) 2018 Cloudbyte. All rights reserved.
 */

#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/fm/fs/zfs.h>
#include <libzfs.h>
#include <zrepl_mgmt.h>

#include "zfs_events.h"

/*
 * Print vdev state change event in user friendly way.
 */
static void
print_state_change(nvlist_t *event)
{
	char	*pool_name;
	char	*vdev_name;
	uint64_t new_state, old_state;

	if (nvlist_lookup_string(event,
	    FM_EREPORT_PAYLOAD_ZFS_POOL, &pool_name) != 0 ||
	    nvlist_lookup_string(event,
	    FM_EREPORT_PAYLOAD_ZFS_VDEV_PATH, &vdev_name) != 0 ||
	    nvlist_lookup_uint64(event,
	    FM_EREPORT_PAYLOAD_ZFS_VDEV_STATE, &new_state) != 0 ||
	    nvlist_lookup_uint64(event,
	    FM_EREPORT_PAYLOAD_ZFS_VDEV_LASTSTATE, &old_state) != 0) {
		LOG_ERR("Invalid content of ZFS state change event");
	} else {
		LOG_INFO("Vdev %s in pool %s changed state: %s -> %s",
		    vdev_name, pool_name,
		    zpool_state_to_name(old_state, VDEV_AUX_NONE),
		    zpool_state_to_name(new_state, VDEV_AUX_NONE));
	}
}

/*
 * Print the event in raw form to stderr.
 */
static void
print_zfs_event(nvlist_t *event)
{
	enum zrepl_log_level lvl = LOG_LEVEL_ERR;
	boolean_t skip = B_FALSE;
	char	*class;

	if (nvlist_lookup_string(event, FM_CLASS, &class) != 0) {
		LOG_ERR("Missing class in zfs ereport");
		nvlist_free(event);
		return;
	}

	if (strcmp(class, FM_EREPORT_CLASS "." ZFS_ERROR_CLASS "."
	    FM_EREPORT_ZFS_CONFIG_CACHE_WRITE) == 0) {
		/*
		 * This event is generated upon every spa configuration
		 * change because zrepl does not have a cache file.
		 */
		skip = B_TRUE;
	} else if (strcmp(class, FM_RSRC_RESOURCE "." ZFS_ERROR_CLASS "."
	    FM_RESOURCE_REMOVED) == 0) {
		lvl = LOG_LEVEL_INFO;
	} else if (strcmp(class, FM_RSRC_RESOURCE "." ZFS_ERROR_CLASS "."
	    FM_RESOURCE_AUTOREPLACE) == 0) {
		lvl = LOG_LEVEL_INFO;
	} else if (strcmp(class, FM_RSRC_RESOURCE "." ZFS_ERROR_CLASS "."
	    FM_RESOURCE_STATECHANGE) == 0) {
		print_state_change(event);
		skip = B_TRUE;
	}

	if (!skip) {
		zrepl_log(lvl, "ZFS event:");
		fm_nvprint(event);
	}
	nvlist_free(event);
}

/*
 * Endless loop in which we wait for new zfs events being generated and print
 * them.
 */
void
zrepl_monitor_errors(void)
{
	zfs_zevent_t	*ze;
	nvlist_t	*event = NULL;
	uint64_t	size, dropped;
	int		rc;

	zfs_zevent_init(&ze);

	while (1) {
		// There is no limit for event size because we are not going to
		// copy it to a preallocated buffer
		size = -1;
		dropped = 0;
		rc = zfs_zevent_next(ze, &event, &size, &dropped);
		if (dropped > 0) {
			LOG_ERR("Dropped %lu zfs events", dropped);
		}
		if (event != NULL) {
			print_zfs_event(event);
			event = NULL;
		}
		if (rc != 0) {
			if (rc == ENOENT) {
				zfs_zevent_wait(ze);
			} else {
				LOG_ERR("Failed to get zfs events: %d", rc);
			}
		}
	}
	zfs_zevent_destroy(ze);
}
