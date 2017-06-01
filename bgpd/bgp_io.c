/* BGP I/O.
 * Implements packet I/O in a consumer pthread.
 * Copyright (C) 2017  Cumulus Networks
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <pthread.h>
#include <sys/time.h>
#include <zebra.h>

#include "hash.h"
#include "log.h"
#include "memory.h"
#include "monotime.h"
#include "network.h"
#include "pqueue.h"
#include "stream.h"
#include "thread.h"

#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgpd.h"

/* forward declarations */
static uint16_t bgp_write(struct peer *);
static uint16_t bgp_read(struct peer *);
static int bgp_process_writes(struct thread *);
static int bgp_process_reads(struct thread *);
static bool validate_header(struct peer *);

/* generic i/o status codes */
#define BGP_IO_TRANS_ERR        (1 << 1) // EAGAIN or similar occurred
#define BGP_IO_FATAL_ERR        (1 << 2) // some kind of fatal TCP error

/* bgp_read() status codes */
#define BGP_IO_READ_HEADER      (1 << 3) // when read a full packet header
#define BGP_IO_READ_FULLPACKET  (1 << 4) // read a full packet

/* Start and stop routines for I/O pthread + control variables
 * ------------------------------------------------------------------------ */
bool bgp_packet_write_thread_run = false;
pthread_mutex_t *work_mtx;

static struct list *read_cancel;
static struct list *write_cancel;

void bgp_io_init()
{
	work_mtx = XCALLOC(MTYPE_TMP, sizeof(pthread_mutex_t));
	pthread_mutex_init(work_mtx, NULL);

	read_cancel = list_new();
	write_cancel = list_new();
}

void *bgp_io_start(void *arg)
{
	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	// we definitely don't want to handle signals
	fpt->master->handle_signals = false;

	bgp_packet_write_thread_run = true;
	struct thread task;

	while (bgp_packet_write_thread_run) {
		if (thread_fetch(fpt->master, &task)) {
			pthread_mutex_lock(work_mtx);
			{
				bool cancel = false;
				struct peer *peer = THREAD_ARG(&task);
				if ((task.func == bgp_process_reads
				     && listnode_lookup(read_cancel, peer))
				    || (task.func == bgp_process_writes
					&& listnode_lookup(write_cancel, peer)))
					cancel = true;

				list_delete_all_node(write_cancel);
				list_delete_all_node(read_cancel);

				if (!cancel)
					thread_call(&task);
			}
			pthread_mutex_unlock(work_mtx);
		}
	}

	return NULL;
}

int bgp_io_stop(void **result, struct frr_pthread *fpt)
{
	fpt->master->spin = false;
	bgp_packet_write_thread_run = false;
	pthread_kill(fpt->thread, SIGINT);
	pthread_join(fpt->thread, result);

	pthread_mutex_unlock(work_mtx);
	pthread_mutex_destroy(work_mtx);

	list_delete(read_cancel);
	list_delete(write_cancel);
	XFREE(MTYPE_TMP, work_mtx);
	return 0;
}
/* ------------------------------------------------------------------------ */

void bgp_writes_on(struct peer *peer)
{
	assert(peer->status != Deleted);
	assert(peer->obuf);
	assert(peer->ibuf);
	assert(peer->ibuf_work);
	assert(!peer->t_connect_check);
	assert(peer->fd);

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	pthread_mutex_lock(work_mtx);
	{
		listnode_delete(write_cancel, peer);
		thread_add_write(fpt->master, bgp_process_writes, peer,
				 peer->fd, &peer->t_write);
		SET_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON);
	}
	pthread_mutex_unlock(work_mtx);
}

void bgp_writes_off(struct peer *peer)
{
	pthread_mutex_lock(work_mtx);
	{
		THREAD_OFF(peer->t_write);
		THREAD_OFF(peer->t_generate_updgrp_packets);
		listnode_add(write_cancel, peer);

		// peer access by us after this point will result in pain
		UNSET_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON);
	}
	pthread_mutex_unlock(work_mtx);
	/* upon return, i/o thread must not access the peer */
}

void bgp_reads_on(struct peer *peer)
{
	assert(peer->status != Deleted);
	assert(peer->ibuf);
	assert(peer->fd);
	assert(peer->ibuf_work);
	assert(stream_get_endp(peer->ibuf_work) == 0);
	assert(peer->obuf);
	assert(!peer->t_connect_check);
	assert(peer->fd);

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	pthread_mutex_lock(work_mtx);
	{
		listnode_delete(read_cancel, peer);
		thread_add_read(fpt->master, bgp_process_reads, peer, peer->fd,
				&peer->t_read);
		SET_FLAG(peer->thread_flags, PEER_THREAD_READS_ON);
	}
	pthread_mutex_unlock(work_mtx);
}

void bgp_reads_off(struct peer *peer)
{
	pthread_mutex_lock(work_mtx);
	{
		THREAD_OFF(peer->t_read);
		THREAD_OFF(peer->t_process_packet);
		listnode_add(read_cancel, peer);

		// peer access by us after this point will result in pain
		UNSET_FLAG(peer->thread_flags, PEER_THREAD_READS_ON);
	}
	pthread_mutex_unlock(work_mtx);
}

/**
 * Called from PTHREAD_IO when select() or poll() determines that the file
 * descriptor is ready to be written to.
 */
static int bgp_process_writes(struct thread *thread)
{
	static struct peer *peer;
	peer = THREAD_ARG(thread);
	uint16_t status;

	if (peer->fd < 0)
		return -1;

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	bool reschedule;
	pthread_mutex_lock(&peer->io_mtx);
	{
		status = bgp_write(peer);
		reschedule = (stream_fifo_head(peer->obuf) != NULL);
	}
	pthread_mutex_unlock(&peer->io_mtx);

	if (CHECK_FLAG(status, BGP_IO_TRANS_ERR)) { /* no problem */
	}

	if (CHECK_FLAG(status, BGP_IO_FATAL_ERR))
		reschedule = 0; // problem

	if (reschedule) {
		thread_add_write(fpt->master, bgp_process_writes, peer,
				 peer->fd, &peer->t_write);
		thread_add_background(bm->master, bgp_generate_updgrp_packets,
				      peer, 0,
				      &peer->t_generate_updgrp_packets);
	}

	return 0;
}

/**
 * Called from PTHREAD_IO when select() or poll() determines that the file
 * descriptor is ready to be read from.
 */
static int bgp_process_reads(struct thread *thread)
{
	static struct peer *peer;
	peer = THREAD_ARG(thread);
	uint16_t status;

	if (peer->fd < 0)
		return -1;

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	bool reschedule = true;

	// execute read
	pthread_mutex_lock(&peer->io_mtx);
	{
		status = bgp_read(peer);
	}
	pthread_mutex_unlock(&peer->io_mtx);

	// check results of read
	bool header_valid = true;

	if (CHECK_FLAG(status, BGP_IO_TRANS_ERR)) { /* no problem */
	}

	if (CHECK_FLAG(status, BGP_IO_FATAL_ERR))
		reschedule = false; // problem

	if (CHECK_FLAG(status, BGP_IO_READ_HEADER)) {
		header_valid = validate_header(peer);
		if (!header_valid) {
			bgp_size_t packetsize =
				MIN((int)stream_get_endp(peer->ibuf_work),
				    BGP_MAX_PACKET_SIZE);
			memcpy(peer->last_reset_cause, peer->ibuf_work->data,
			       packetsize);
			peer->last_reset_cause_size = packetsize;
			// We're tearing the session down, no point in
			// rescheduling.
			// Additionally, bgp_read() will use the TLV if it's
			// present to
			// determine how much to read; if this is corrupt, we'll
			// crash the
			// program.
			reschedule = false;
		}
	}

	// if we read a full packet, push it onto peer->ibuf, reset our WiP
	// buffer
	// and schedule a job to process it on the main thread
	if (header_valid && CHECK_FLAG(status, BGP_IO_READ_FULLPACKET)) {
		pthread_mutex_lock(&peer->io_mtx);
		{
			stream_fifo_push(peer->ibuf,
					 stream_dup(peer->ibuf_work));
		}
		pthread_mutex_unlock(&peer->io_mtx);
		stream_reset(peer->ibuf_work);
		assert(stream_get_endp(peer->ibuf_work) == 0);

		thread_add_background(bm->master, bgp_process_packet, peer, 0,
				      &peer->t_process_packet);
	}

	if (reschedule)
		thread_add_read(fpt->master, bgp_process_reads, peer, peer->fd,
				&peer->t_read);

	return 0;
}

/**
 * Flush peer output buffer.
 *
 * This function pops packets off of peer->obuf and writes them to peer->fd.
 * The amount of packets written is equal to the minimum of peer->wpkt_quanta
 * and the number of packets on the output buffer, unless an error occurs.
 *
 * If write() returns an error, the appropriate FSM event is generated.
 *
 * The return value is equal to the number of packets written
 * (which may be zero).
 */
static uint16_t bgp_write(struct peer *peer)
{
	u_char type;
	struct stream *s;
	int num;
	int update_last_write = 0;
	unsigned int count = 0;
	unsigned int oc = 0;
	uint16_t status = 0;

	while (count < peer->bgp->wpkt_quanta
	       && (s = stream_fifo_head(peer->obuf))) {
		int writenum;
		do {
			writenum = stream_get_endp(s) - stream_get_getp(s);
			num = write(peer->fd, STREAM_PNT(s), writenum);

			if (num < 0) {
				if (!ERRNO_IO_RETRY(errno)) {
					BGP_EVENT_ADD(peer, TCP_fatal_error);
					SET_FLAG(status, BGP_IO_FATAL_ERR);
				} else {
					SET_FLAG(status, BGP_IO_TRANS_ERR);
				}

				goto done;
			} else if (num != writenum) // incomplete write
				stream_forward_getp(s, num);

		} while (num != writenum);

		/* Retrieve BGP packet type. */
		stream_set_getp(s, BGP_MARKER_SIZE + 2);
		type = stream_getc(s);

		switch (type) {
		case BGP_MSG_OPEN:
			peer->open_out++;
			break;
		case BGP_MSG_UPDATE:
			peer->update_out++;
			break;
		case BGP_MSG_NOTIFY:
			peer->notify_out++;
			/* Double start timer. */
			peer->v_start *= 2;

			/* Overflow check. */
			if (peer->v_start >= (60 * 2))
				peer->v_start = (60 * 2);

			/* Handle Graceful Restart case where the state changes
			   to
			   Connect instead of Idle */
			/* Flush any existing events */
			BGP_EVENT_ADD(peer, BGP_Stop);
			goto done;

		case BGP_MSG_KEEPALIVE:
			peer->keepalive_out++;
			break;
		case BGP_MSG_ROUTE_REFRESH_NEW:
		case BGP_MSG_ROUTE_REFRESH_OLD:
			peer->refresh_out++;
			break;
		case BGP_MSG_CAPABILITY:
			peer->dynamic_cap_out++;
			break;
		}

		count++;

		stream_free(stream_fifo_pop(peer->obuf));
		update_last_write = 1;
	}

done : {
	/* Update last_update if UPDATEs were written. */
	if (peer->update_out > oc)
		peer->last_update = bgp_clock();

	/* If we TXed any flavor of packet update last_write */
	if (update_last_write)
		peer->last_write = bgp_clock();
}

	return status;
}

/**
 * Reads <= 1 packet worth of data from peer->fd into peer->ibuf_work.
 *
 * @return whether a full packet was read
 */
static uint16_t bgp_read(struct peer *peer)
{
	int readsize; // how many bytes we want to read
	int nbytes;   // how many bytes we actually read
	bool have_header = false;
	uint16_t status = 0;

	if (stream_get_endp(peer->ibuf_work) < BGP_HEADER_SIZE)
		readsize = BGP_HEADER_SIZE - stream_get_endp(peer->ibuf_work);
	else {
		// retrieve packet length from tlv and compute # bytes we still
		// need
		u_int16_t mlen =
			stream_getw_from(peer->ibuf_work, BGP_MARKER_SIZE);
		readsize = mlen - stream_get_endp(peer->ibuf_work);
		have_header = true;
	}

	nbytes = stream_read_try(peer->ibuf_work, peer->fd, readsize);

	if (nbytes <= 0) // handle errors
	{
		switch (nbytes) {
		case -1: // fatal error; tear down the session
			zlog_err("%s [Error] bgp_read_packet error: %s",
				 peer->host, safe_strerror(errno));

			if (peer->status == Established) {
				if (CHECK_FLAG(peer->sflags,
					       PEER_STATUS_NSF_MODE)) {
					peer->last_reset =
						PEER_DOWN_NSF_CLOSE_SESSION;
					SET_FLAG(peer->sflags,
						 PEER_STATUS_NSF_WAIT);
				} else
					peer->last_reset =
						PEER_DOWN_CLOSE_SESSION;
			}

			BGP_EVENT_ADD(peer, TCP_fatal_error);
			SET_FLAG(status, BGP_IO_FATAL_ERR);
			break;

		case 0: // TCP session closed
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s [Event] BGP connection closed fd %d",
					peer->host, peer->fd);

			if (peer->status == Established) {
				if (CHECK_FLAG(peer->sflags,
					       PEER_STATUS_NSF_MODE)) {
					peer->last_reset =
						PEER_DOWN_NSF_CLOSE_SESSION;
					SET_FLAG(peer->sflags,
						 PEER_STATUS_NSF_WAIT);
				} else
					peer->last_reset =
						PEER_DOWN_CLOSE_SESSION;
			}

			BGP_EVENT_ADD(peer, TCP_connection_closed);
			SET_FLAG(status, BGP_IO_FATAL_ERR);
			break;

		case -2: // temporary error; come back later
			SET_FLAG(status, BGP_IO_TRANS_ERR);
			break;
		default:
			break;
		}

		return status;
	}

	// If we didn't have the header before read(), and now we do, set the
	// appropriate flag. The caller must validate the header for us.
	if (!have_header
	    && stream_get_endp(peer->ibuf_work) >= BGP_HEADER_SIZE) {
		SET_FLAG(status, BGP_IO_READ_HEADER);
		have_header = true;
	}
	// If we read the # of bytes specified in the tlv, we have read a full
	// packet.
	//
	// Note that the header may not have been validated here. This flag
	// means
	// ONLY that we read the # of bytes specified in the header; if the
	// header is
	// not valid, the packet MUST NOT be processed further.
	if (have_header && (stream_getw_from(peer->ibuf_work, BGP_MARKER_SIZE)
			    == stream_get_endp(peer->ibuf_work)))
		SET_FLAG(status, BGP_IO_READ_FULLPACKET);

	return status;
}

/*
 * Called after we have read a BGP packet header. Validates marker, message
 * type and packet length. If any of these aren't correct, sends a notify.
 */
static bool validate_header(struct peer *peer)
{
	u_int16_t size, type;

	static uint8_t marker[BGP_MARKER_SIZE] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if (memcmp(marker, peer->ibuf_work->data, BGP_MARKER_SIZE) != 0) {
		bgp_notify_send(peer, BGP_NOTIFY_HEADER_ERR,
				BGP_NOTIFY_HEADER_NOT_SYNC);
		return false;
	}

	/* Get size and type. */
	size = stream_getw_from(peer->ibuf_work, BGP_MARKER_SIZE);
	type = stream_getc_from(peer->ibuf_work, BGP_MARKER_SIZE + 2);

	/* BGP type check. */
	if (type != BGP_MSG_OPEN && type != BGP_MSG_UPDATE
	    && type != BGP_MSG_NOTIFY && type != BGP_MSG_KEEPALIVE
	    && type != BGP_MSG_ROUTE_REFRESH_NEW
	    && type != BGP_MSG_ROUTE_REFRESH_OLD
	    && type != BGP_MSG_CAPABILITY) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s unknown message type 0x%02x", peer->host,
				   type);

		bgp_notify_send_with_data(peer, BGP_NOTIFY_HEADER_ERR,
					  BGP_NOTIFY_HEADER_BAD_MESTYPE,
					  (u_char *)&type, 1);
		return false;
	}

	/* Mimimum packet length check. */
	if ((size < BGP_HEADER_SIZE) || (size > BGP_MAX_PACKET_SIZE)
	    || (type == BGP_MSG_OPEN && size < BGP_MSG_OPEN_MIN_SIZE)
	    || (type == BGP_MSG_UPDATE && size < BGP_MSG_UPDATE_MIN_SIZE)
	    || (type == BGP_MSG_NOTIFY && size < BGP_MSG_NOTIFY_MIN_SIZE)
	    || (type == BGP_MSG_KEEPALIVE && size != BGP_MSG_KEEPALIVE_MIN_SIZE)
	    || (type == BGP_MSG_ROUTE_REFRESH_NEW
		&& size < BGP_MSG_ROUTE_REFRESH_MIN_SIZE)
	    || (type == BGP_MSG_ROUTE_REFRESH_OLD
		&& size < BGP_MSG_ROUTE_REFRESH_MIN_SIZE)
	    || (type == BGP_MSG_CAPABILITY
		&& size < BGP_MSG_CAPABILITY_MIN_SIZE)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s bad message length - %d for %s",
				   peer->host, size,
				   type == 128 ? "ROUTE-REFRESH"
					       : bgp_type_str[(int)type]);

		bgp_notify_send_with_data(peer, BGP_NOTIFY_HEADER_ERR,
					  BGP_NOTIFY_HEADER_BAD_MESLEN,
					  (u_char *)&size, 2);
		return false;
	}

	return true;
}
