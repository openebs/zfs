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

#include <scsi/scsi.h>
#undef VERIFY	/* VERIFY macro name collision - we want the ZFS macro */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/vdev_impl.h>
#include <sys/zio.h>
#include <sys/abd.h>
#include <sys/kstat.h>
#include <sys/vdev_disk_aio.h>

#include <sys/poll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <libaio.h>
#include <linux/fs.h>
#include <rte_ring.h>
#include <scsi/sg.h>

/*
 * This is a max number of inflight IOs for a single vdev device and it governs
 * the size of input ring buffer, AIO context and other structures used in this
 * vdev backend.
 */
extern const uint32_t zfs_vdev_max_active;

/*
 * When having this many queued IOs on input we submit them to kernel.
 * By default it is set to one which means we don't try to group IOs,
 * which gives better result for synchronous workloads and faster CPUs.
 */
#define	AIO_QUEUE_HIGH_WM	1

/*
 * poll sleep interval makes difference only if high wm above is greater
 * than 1. In opposite case it does not have much impact as everything
 * is driven purely by events.
 *
 * NOTE: Empirically was found that 100us works well in absence of events
 * (a kind of semi-busy-poll).
 */
#define	POLL_SLEEP	100000000

/* SCSI flush command timeout in milliseconds */
#define	SCSI_FLUSH_TIMEOUT	1000
#define	SCSI_SENSE_BUF_LEN	32

/*
 * Virtual device vector for disks accessed from userland using linux aio(7) API
 */

typedef struct vdev_disk_aio {
	int vda_fd;
	/* AIO context used for submitting AIOs and polling */
	io_context_t vda_io_ctx;
	boolean_t vda_stop_polling;
	uintptr_t vda_poller_tid;
	/* Support for submitting multiple IOs in one syscall */
	uintptr_t vda_submitter_tid;
	int vda_submit_fd;	/* eventfd for waking up IO submitter */
	uint32_t vda_zio_next;	/* next zio to be submitted to kernel */
				/* read & written only from poller thread */
	uint32_t vda_zio_top;	/* latest incoming zio from uzfs */
	struct rte_ring *vda_ring; /* ring buffer to enqueue/dequeue zio */
	boolean_t vda_noflush;	/* disk cache flush not supported */
} vdev_disk_aio_t;

typedef struct aio_task {
	zio_t *zio;
	void *buf;
	struct iocb iocb;
} aio_task_t;

/*
 * AIO kstats help analysing performance of aio vdev backend.
 */
typedef struct vda_stats {
	kstat_named_t vda_stat_userspace_polls;
	kstat_named_t vda_stat_kernel_polls;
	kstat_named_t vda_stat_flush_errors;
} vda_stats_t;

static vda_stats_t vda_stats = {
	{ "userspace_polls",	KSTAT_DATA_UINT64 },
	{ "kernel_polls",	KSTAT_DATA_UINT64 },
	{ "flush_errors",	KSTAT_DATA_UINT64 },
};

#define	VDA_STAT_BUMP(stat)	atomic_inc_64(&vda_stats.stat.value.ui64)

kstat_t *vda_ksp = NULL;

/*
 * Process a single result from asynchronous IO.
 */
static void
vdev_disk_aio_done(aio_task_t *task, int64_t res)
{
	zio_t *zio = task->zio;

	if (zio->io_type == ZIO_TYPE_IOCTL) {
		if (res != 0) {
			zio->io_error = (SET_ERROR(-res));
		}
	} else {
		if (zio->io_type == ZIO_TYPE_READ)
			abd_return_buf_copy(zio->io_abd, task->buf,
			    zio->io_size);
		else if (zio->io_type == ZIO_TYPE_WRITE)
			abd_return_buf(zio->io_abd, task->buf, zio->io_size);
		else
			ASSERT(0);

		if (res < 0) {
			zio->io_error = (SET_ERROR(-res));
		} else if (res != zio->io_size) {
			zio->io_error = (SET_ERROR(ENOSPC));
		}

	}

	/*
	 * Perf optimisation: For reads there is checksum verify pipeline
	 * stage which is CPU intensive and could delay next poll considerably
	 * hence it is executed asynchronously, however for other operations
	 * (write and ioctl) it is faster to finish zio directly (synchronously)
	 * than to dispatch the work to a separate thread.
	 */
	if (zio->io_type == ZIO_TYPE_READ)
		zio_interrupt(zio);
	else
		zio_execute(zio);

	kmem_free(task, sizeof (aio_task_t));
}

/*
 * A copy of aio ring structure to be able to access aio events from userland.
 */
struct aio_ring {
	unsigned id;	/* kernel internal index number */
	unsigned nr;	/* number of io_events */
	unsigned head;
	unsigned tail;

	unsigned magic;
	unsigned compat_features;
	unsigned incompat_features;
	unsigned header_length;  /* size of aio_ring */

	struct io_event events[0];
};

#define	AIO_RING_MAGIC	0xa10a10a1

static int
user_io_getevents(io_context_t io_ctx, struct io_event *events)
{
	long i = 0;
	unsigned head;
	struct aio_ring *ring = (struct aio_ring *)io_ctx;

	while (i < zfs_vdev_max_active) {
		head = ring->head;

		if (head == ring->tail) {
			/* There are no more completions */
			break;
		} else {
			/* There is another completion to reap */
			events[i] = ring->events[head];
			/* read barrier */
			asm volatile("": : :"memory");
			ring->head = (head + 1) % ring->nr;
			i++;
		}
	}

	return (i);
}

/*
 * Poll for asynchronous IO done events and dispatch completed IOs to zio
 * pipeline.
 */
static void
vdev_disk_aio_poller(void *arg)
{
	vdev_disk_aio_t *vda = arg;
	struct io_event *events;
	struct timespec timeout;
	int nr;

	prctl(PR_SET_NAME, "aio_poller", 0, 0, 0);

	/* allocated on heap not to exceed recommended frame size */
	events = kmem_alloc(zfs_vdev_max_active * sizeof (struct io_event),
	    KM_SLEEP);

	while (!vda->vda_stop_polling) {
		timeout.tv_sec = 0;
		timeout.tv_nsec = POLL_SLEEP;
		nr = 0;

		/* First we try non-blocking userspace poll which is fast */
		if (((struct aio_ring *)(vda->vda_io_ctx))->magic ==
		    AIO_RING_MAGIC) {
			nr = user_io_getevents(vda->vda_io_ctx, events);
		}
		if (nr <= 0) {
			/* Do blocking kernel poll */
			nr = io_getevents(vda->vda_io_ctx, 1,
			    zfs_vdev_max_active, events, &timeout);
			VDA_STAT_BUMP(vda_stat_kernel_polls);
		} else {
			VDA_STAT_BUMP(vda_stat_userspace_polls);
		}

		if (nr < 0) {
			int error = -nr;

			/* all errors except EINTR are unrecoverable */
			if (error == EINTR) {
				continue;
			} else {
				fprintf(stderr,
				    "Failed when polling for AIO events: %d\n",
				    error);
				break;
			}
		}
		ASSERT3P(nr, <=, zfs_vdev_max_active);

		for (int i = 0; i < nr; i++) {
			vdev_disk_aio_done(events[i].data, events[i].res);
		}
	}

	kmem_free(events, zfs_vdev_max_active * sizeof (struct io_event));
	vda->vda_poller_tid = 0;
	thread_exit();
}

/*
 * Submit all queued ZIOs to kernel and reset length of ZIO queue.
 *
 * Passed zio buffer is just an optimization to avoid (de)allocation of
 * large zio array on each invocation of the function.
 */
static void
vdev_disk_aio_submit(vdev_disk_aio_t *vda, zio_t **zios, int nr,
    struct iocb **iocbs)
{
	int n = 0;

	for (n = 0; n < nr; n++) {
		aio_task_t *task;
		zio_t *zio = zios[n];
		ASSERT3P(zio->io_vd->vdev_tsd, ==, vda);

		/*
		 * Prepare AIO command control block.
		 */
		task = kmem_alloc(sizeof (aio_task_t), KM_SLEEP);
		task->zio = zio;
		task->buf = NULL;
		iocbs[n] = &task->iocb;

		switch (zio->io_type) {
		case ZIO_TYPE_WRITE:
			task->buf = abd_borrow_buf_copy(zio->io_abd,
			    zio->io_size);
			io_prep_pwrite(iocbs[n], vda->vda_fd, task->buf,
			    zio->io_size, zio->io_offset);
			break;
		case ZIO_TYPE_READ:
			task->buf = abd_borrow_buf(zio->io_abd,
			    zio->io_size);
			io_prep_pread(iocbs[n], vda->vda_fd, task->buf,
			    zio->io_size, zio->io_offset);
			break;
		default:
			ASSERT(0);
		}

		/*
		 * prep functions above reset data pointer
		 * set it again
		 */
		iocbs[n]->data = task;
	}

	/*
	 * Submit async IO.
	 */
	nr = io_submit(vda->vda_io_ctx, n, iocbs);
	if (nr < n) {
		int neg_error;

		if (nr < 0) {
			neg_error = nr;
			nr = 0;
		} else {
			/* No error but the control block was not submitted */
			neg_error = -EAGAIN;
		}

		for (int i = nr; i < n; i++) {
			aio_task_t *task = (aio_task_t *)iocbs[i]->data;
			vdev_disk_aio_done(task, neg_error);
		}
	}
}

/*
 * Asynchronous dispatch of IO to kernel. This is done to submit IOs in groups
 * thus minimize overhead of io_submit call.
 */
static void
vdev_disk_aio_submitter(void *arg)
{
	vdev_disk_aio_t *vda = arg;
	zio_t **zios_buf;
	struct pollfd fds;
	uint64_t poll_data;
	struct timespec ts;
	struct iocb **iocbs;
	int event_came;
	int rc;

	prctl(PR_SET_NAME, "aio_submitter", 0, 0, 0);

	/* allocated on heap not to exceed recommended frame size */
	zios_buf = kmem_alloc(zfs_vdev_max_active * sizeof (zio_t *), KM_SLEEP);
	/* Preallocated array of iocbs for use in submit to run faster */
	iocbs = kmem_alloc(zfs_vdev_max_active * sizeof (struct iocb *),
	    KM_SLEEP);

	if (AIO_QUEUE_HIGH_WM > 1) {
		ts.tv_sec = 0;
		ts.tv_nsec = POLL_SLEEP;
	} else {
		ts.tv_sec = 1;
		ts.tv_nsec =  0;
	}

	while (!vda->vda_stop_polling) {
		fds.fd = vda->vda_submit_fd;
		fds.events = POLLIN;
		fds.revents = 0;
		event_came = B_FALSE;

		rc = ppoll(&fds, 1, &ts, NULL);
		if (rc < 0) {
			perror("ppoll in submitter");
		} else if (rc > 0 && fds.revents == POLLIN) {
			rc = read(vda->vda_submit_fd, &poll_data,
			    sizeof (poll_data));
			ASSERT3P(rc, ==, sizeof (poll_data));
			event_came = B_TRUE;
		}

		/*
		 * Dequeue all ZIOs from ring buffer even if there was no event
		 * (and if high-wm > 1), because we want to guarantee that every
		 * IO request is dispatched within reasonable time frame.
		 */
		if (event_came || AIO_QUEUE_HIGH_WM > 1) {
			/*
			 * Using single consumer since there is only one
			 * submitter thread dequeuing from the ring buffer.
			 */
			rc = rte_ring_sc_dequeue_burst(vda->vda_ring,
			    (void **) zios_buf, zfs_vdev_max_active, NULL);
			if (rc > 0)
				vdev_disk_aio_submit(vda, zios_buf, rc, iocbs);
		}
	}

	kmem_free(zios_buf, zfs_vdev_max_active * sizeof (zio_t *));
	kmem_free(iocbs, zfs_vdev_max_active * sizeof (struct iocb *));
	vda->vda_submitter_tid = 0;
	thread_exit();
}

static void
kick_submitter(vdev_disk_aio_t *vda)
{
	uint64_t data = 1;
	int rc;

	rc = write(vda->vda_submit_fd, &data, sizeof (data));
	assert(rc == sizeof (data));
}

/*
 * This flush write-cache function works only for true SCSI disks (sd driver):
 *
 *  *) NVMe devices don't support the ioctl,
 *  *) ATA/SATA disks haven't been tested.
 *
 * NOTE: This is called synchronously in zio pipeline. Attempt to execute
 * flush asynchronously on behalf of taskq thread resulted in -10%
 * performance regression for sync workloads.
 */
static void
vdev_disk_aio_flush(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_disk_aio_t *vda = vd->vdev_tsd;

	struct sg_io_hdr io_hdr;
	unsigned char scCmdBlk[] =
	    {SYNCHRONIZE_CACHE, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	unsigned char sense_b[SCSI_SENSE_BUF_LEN];

	memset(&io_hdr, 0, sizeof (io_hdr));

	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = sizeof (scCmdBlk);
	io_hdr.cmdp = scCmdBlk;
	io_hdr.sbp = sense_b;
	io_hdr.mx_sb_len = sizeof (sense_b);
	io_hdr.dxfer_direction = SG_DXFER_NONE;
	io_hdr.timeout = SCSI_FLUSH_TIMEOUT;

	if (ioctl(vda->vda_fd, SG_IO, &io_hdr) < 0) {
		if (errno == EINVAL || errno == ENOTTY) {
			vda->vda_noflush = B_TRUE;
		} else {
			VDA_STAT_BUMP(vda_stat_flush_errors);
			zio->io_error = errno;
		}
	} else if (io_hdr.status != GOOD) {
		fprintf(stderr, "Synchronize cache SCSI command failed "
		    "for %s\n", vd->vdev_path);
		if (io_hdr.status == CHECK_CONDITION) {
			char buf[3 * SCSI_SENSE_BUF_LEN];
			int len = MIN(io_hdr.sb_len_wr, SCSI_SENSE_BUF_LEN);
			unsigned char resp_code;
			unsigned char sense_key = 0;

			for (int i = 0; i < len; i++) {
				snprintf(&buf[3 * i], 4, " %02X",
				    io_hdr.sbp[i]);
			}
			fprintf(stderr, "Sense data:%s\n", buf);

			resp_code = io_hdr.sbp[0] & 0x7f;
			if (resp_code >= 0x72) {	/* descriptor format */
				if (len > 1)
					sense_key = (0xf & io_hdr.sbp[1]);
			} else {			/* fixed format */
				if (len > 2)
					sense_key = (0xf & io_hdr.sbp[2]);
			}
			if (sense_key == ILLEGAL_REQUEST) {
				vda->vda_noflush = B_TRUE;
			} else {
				VDA_STAT_BUMP(vda_stat_flush_errors);
				zio->io_error = EIO;
			}
		} else {
			VDA_STAT_BUMP(vda_stat_flush_errors);
			zio->io_error = EIO;
		}
	}

	if (vda->vda_noflush) {
		fprintf(stderr, "Disk %s does not support synchronize "
		    "cache SCSI command\n", vd->vdev_path);
	}

	zio_execute(zio);
}

/*
 * We probably can't do anything better from userland than opening the device
 * to prevent it from going away. So hold and rele are noops.
 */
static void
vdev_disk_aio_hold(vdev_t *vd)
{
	ASSERT(vd->vdev_path != NULL);
}

static void
vdev_disk_aio_rele(vdev_t *vd)
{
	ASSERT(vd->vdev_path != NULL);
}

/*
 * Opens dev file, creates AIO context and poller thread.
 */
static int
vdev_disk_aio_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *ashift)
{
	vdev_disk_aio_t *vda;
	unsigned short isrot = 0;
	int err;

	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (SET_ERROR(EINVAL));
	}

	/*
	 * Reopen the device if it's not currently open.  Otherwise,
	 * just update the physical size of the device.
	 */
	if (vd->vdev_tsd != NULL) {
		ASSERT(vd->vdev_reopening);
		vda = vd->vdev_tsd;
		goto skip_open;
	}

	vda = kmem_zalloc(sizeof (vdev_disk_aio_t), KM_SLEEP);

	ASSERT(vd->vdev_path != NULL && vd->vdev_path[0] == '/');
	vda->vda_fd = open(vd->vdev_path,
	    ((spa_mode(vd->vdev_spa) & FWRITE) != 0) ? O_RDWR|O_DIRECT :
	    O_RDONLY|O_DIRECT);

	if (vda->vda_fd < 0) {
		kmem_free(vda, sizeof (vdev_disk_aio_t));
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(errno));
	}

	/*
	 * Note: code in fio aio plugin suggests that for new kernels we can
	 * pass INTMAX as limit here and use max limit allowed by the kernel.
	 * However for userspace polling we need some kind of limit.
	 */
	err = io_setup(zfs_vdev_max_active, &vda->vda_io_ctx);
	if (err != 0) {
		fprintf(stderr, "Failed to initialize AIO context: %d\n", -err);
		close(vda->vda_fd);
		kmem_free(vda, sizeof (vdev_disk_aio_t));
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(-err));
	}

	/* Create lockless ring for input ZIOs */
	vda->vda_ring = rte_ring_create("aio_submit_ring", zfs_vdev_max_active,
	    -1, RING_F_EXACT_SZ);
	if (!vda->vda_ring) {
		fprintf(stderr, "Failed to create aio_submit ring\n");
		(void) io_destroy(vda->vda_io_ctx);
		close(vda->vda_fd);
		kmem_free(vda, sizeof (vdev_disk_aio_t));
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(ENOMEM));
	}
	vda->vda_submit_fd = eventfd(0, EFD_NONBLOCK);
	if (vda->vda_submit_fd < 0) {
		fprintf(stderr, "Failed to create eventfd descriptor\n");
		rte_ring_free(vda->vda_ring);
		(void) io_destroy(vda->vda_io_ctx);
		close(vda->vda_fd);
		kmem_free(vda, sizeof (vdev_disk_aio_t));
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(ENOMEM));
	}

	vda->vda_noflush = B_FALSE;
	vda->vda_stop_polling = B_FALSE;
	vda->vda_poller_tid = (uintptr_t)thread_create(NULL, 0,
	    vdev_disk_aio_poller, vda, 0, &p0, TS_RUN, 0);
	vda->vda_submitter_tid = (uintptr_t)thread_create(NULL, 0,
	    vdev_disk_aio_submitter, vda, 0, &p0, TS_RUN, 0);

	vd->vdev_tsd = vda;

skip_open:
	if (ioctl(vda->vda_fd, BLKSSZGET, ashift) != 0) {
		(void) close(vda->vda_fd);
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(errno));
	}
	if (ioctl(vda->vda_fd, BLKGETSIZE64, psize) != 0) {
		(void) close(vda->vda_fd);
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(errno));
	}
	if (ioctl(vda->vda_fd, BLKROTATIONAL, &isrot) != 0) {
		(void) close(vda->vda_fd);
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(errno));
	}

	*ashift = highbit64(MAX(*ashift, SPA_MINBLOCKSIZE)) - 1;
	*max_psize = *psize;
	vd->vdev_nonrot = !isrot;

	return (0);
}

/*
 * Waits for poller & submitter thread to exit and destroys AIO context.
 */
static void
vdev_disk_aio_close(vdev_t *vd)
{
	vdev_disk_aio_t *vda = vd->vdev_tsd;
	struct timespec ts;

	if (vd->vdev_reopening || vda == NULL)
		return;

	ASSERT3P(vda->vda_zio_next, ==, vda->vda_zio_top);
	ts.tv_sec = 0;
	ts.tv_nsec = 100000000;  // 100ms

	vda->vda_stop_polling = B_TRUE;
	kick_submitter(vda);
	while (vda->vda_poller_tid != 0 || vda->vda_submitter_tid != 0) {
		nanosleep(&ts, NULL);
	}

	(void) close(vda->vda_submit_fd);
	(void) io_destroy(vda->vda_io_ctx);
	(void) close(vda->vda_fd);

	vd->vdev_delayed_close = B_FALSE;

	rte_ring_free(vda->vda_ring);
	kmem_free(vda, sizeof (vdev_disk_aio_t));
	vd->vdev_tsd = NULL;
}

/*
 * Check and put valid IOs to submit queue.
 */
static void
vdev_disk_aio_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_disk_aio_t *vda = vd->vdev_tsd;
	hrtime_t delta = gethrtime();
	zio_type_t type = zio->io_type;
	uint64_t psize = zio->io_size;

	/*
	 * Check operation type.
	 */
	switch (zio->io_type) {
	case ZIO_TYPE_IOCTL:
		if (!vdev_readable(vd)) {
			zio->io_error = (SET_ERROR(ENXIO));
			zio_interrupt(zio);
			return;
		}
		if (zio->io_cmd != DKIOCFLUSHWRITECACHE) {
			zio->io_error = (SET_ERROR(ENOTSUP));
			zio_execute(zio);
			return;
		}
		/*
		 * Flush suggests that higher level code has finished writing
		 * and is waiting for data to be written to disk to continue.
		 * So submit IOs which have been queued in input ring buffer.
		 */
		if (AIO_QUEUE_HIGH_WM > 1)
			kick_submitter(vda);

		/*
		 * fsync for device files is not be needed because of O_DIRECT
		 * open flag. But we still need to flush disk write-cache.
		 */
		if (!vda->vda_noflush) {
			vdev_disk_aio_flush(zio);
		} else {
			zio_execute(zio);
		}
		return;

	case ZIO_TYPE_WRITE:
		break;
	case ZIO_TYPE_READ:
		break;
	default:
		zio->io_error = (SET_ERROR(ENOTSUP));
		zio_interrupt(zio);
		break;
	}

#if defined(_DISABLE_WRITES)
	if ((zio->io_bookmark.zb_objset != 0) && (zio->io_bookmark.zb_object == 1) &&
	    (zio->io_bookmark.zb_level == 0)) {
		if (zio->io_type == ZIO_TYPE_READ)
			zio_interrupt(zio);
		else
			zio_execute(zio);
	}
#else
	/*
	 * Enqueue zio and poller thread will take care of it.
	 */

	if (rte_ring_mp_enqueue(vda->vda_ring, (void **) &zio)) {
		fprintf(stderr, "Failed to enqueue zio in ring\n");
		zio->io_error = (SET_ERROR(EBUSY));
		zio_interrupt(zio);
	}
	if (rte_ring_count(vda->vda_ring) >= AIO_QUEUE_HIGH_WM) {
		kick_submitter(vda);
	}
#endif

	delta = gethrtime() - delta;
	if (zio->io_bookmark.zb_level == 0) {
		if (zio->io_bookmark.zb_objset != 0)
			spa_l0_add_disk_values(zio->io_spa, type, psize, delta);
		else
			spa_meta_l0_add_disk_values(zio->io_spa, type, psize, delta);
	} else {
		if (zio->io_bookmark.zb_objset != 0)
			spa_non_l0_add_disk_values(zio->io_spa, type, psize, delta);
		else
			spa_meta_non_l0_add_disk_values(zio->io_spa, type, psize, delta);
	}
}

/* ARGSUSED */
static void
vdev_disk_zio_done(zio_t *zio)
{
	/*
	 * This callback is used to trigger device removal or do another
	 * smart things in case that zio ends up with EIO error.
	 * As of now nothing implemented here.
	 */
}

void
vdev_disk_aio_init(void)
{
	vda_ksp = kstat_create("zfs", 0, "vdev_aio_stats", "misc",
	    KSTAT_TYPE_NAMED, sizeof (vda_stats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (vda_ksp != NULL) {
		vda_ksp->ks_data = &vda_stats;
		kstat_install(vda_ksp);
	}
}

void
vdev_disk_aio_fini(void)
{
	if (vda_ksp != NULL) {
		kstat_delete(vda_ksp);
		vda_ksp = NULL;
	}
}

vdev_ops_t vdev_disk_ops = {
	vdev_disk_aio_open,
	vdev_disk_aio_close,
	vdev_default_asize,
	vdev_disk_aio_start,
	vdev_disk_zio_done,
	NULL,
	NULL,
	vdev_disk_aio_hold,
	vdev_disk_aio_rele,
	VDEV_TYPE_DISK,		/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};
