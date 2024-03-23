// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 definitions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 * Copyright (C) 2020  Masakazu Asama
 */

#include <zebra.h>

#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "srv6.h"
#include "zebra/debug.h"
#include "zebra/zapi_msg.h"
#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_srv6.h"
#include "zebra/zebra_errors.h"
#include "zebra/ge_netlink.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>


DEFINE_QOBJ_TYPE(zebra_srv6_locator);
DEFINE_QOBJ_TYPE(zebra_srv6_sid_format);
DEFINE_MGROUP(SRV6_MGR, "SRv6 Manager");
DEFINE_MTYPE_STATIC(SRV6_MGR, SRV6M_CHUNK, "SRv6 Manager Chunk");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_LOCATOR, "Zebra SRv6 locator");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_FORMAT, "SRv6 SID format");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_BLOCK, "SRv6 SID block");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_FUNC, "SRv6 SID function");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_USID_WLIB,
		    "SRv6 uSID Wide LIB information");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID, "SRv6 SID");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_CTX, "SRv6 SID context");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_OWNER, "SRv6 SID owner");

/* define hooks for the basic API, so that it can be specialized or served
 * externally
 */

DEFINE_HOOK(srv6_manager_client_connect,
	    (struct zserv *client, vrf_id_t vrf_id),
	    (client, vrf_id));
DEFINE_HOOK(srv6_manager_client_disconnect,
	    (struct zserv *client), (client));
DEFINE_HOOK(srv6_manager_get_chunk,
	    (struct srv6_locator **loc,
	     struct zserv *client,
	     const char *locator_name,
	     vrf_id_t vrf_id),
	    (loc, client, locator_name, vrf_id));
DEFINE_HOOK(srv6_manager_release_chunk,
	    (struct zserv *client,
	     const char *locator_name,
	     vrf_id_t vrf_id),
	    (client, locator_name, vrf_id));

/* define wrappers to be called in zapi_msg.c (as hooks must be called in
 * source file where they were defined)
 */

void srv6_manager_client_connect_call(struct zserv *client, vrf_id_t vrf_id)
{
	hook_call(srv6_manager_client_connect, client, vrf_id);
}

void srv6_manager_get_locator_chunk_call(struct srv6_locator **loc,
					 struct zserv *client,
					 const char *locator_name,
					 vrf_id_t vrf_id)
{
	hook_call(srv6_manager_get_chunk, loc, client, locator_name, vrf_id);
}

void srv6_manager_release_locator_chunk_call(struct zserv *client,
					     const char *locator_name,
					     vrf_id_t vrf_id)
{
	hook_call(srv6_manager_release_chunk, client, locator_name, vrf_id);
}

int srv6_manager_client_disconnect_cb(struct zserv *client)
{
	hook_call(srv6_manager_client_disconnect, client);
	return 0;
}

static int zebra_srv6_cleanup(struct zserv *client)
{
	return 0;
}

/* --- SRv6 SID owner management functions -------------------------------- */

void zebra_srv6_sid_owner_free(struct zebra_srv6_sid_owner *owner)
{
	XFREE(MTYPE_ZEBRA_SRV6_SID_OWNER, owner);
}

/**
 * Free an SRv6 SID owner object.
 *
 * @param val SRv6 SID owner to be freed
 */
void delete_zebra_srv6_sid_owner(void *val)
{
	zebra_srv6_sid_owner_free((struct zebra_srv6_sid_owner *)val);
}

/**
 * Check whether an SRv6 SID is owned by a specific protocol daemon or not.
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param sid SRv6 SID to verify
 * @return True if the SID is owned by the protocol daemon, False otherwise
 */
bool sid_is_owned_by_proto(uint8_t proto, unsigned short instance,
			   struct zebra_srv6_sid *sid)
{
	struct zebra_srv6_sid_owner *owner;
	struct listnode *node;

	if (!sid)
		return false;

	for (ALL_LIST_ELEMENTS_RO(sid->owners, node, owner)) {
		if (owner->proto == proto && owner->instance == instance)
			return true;
	}

	return false;
}

/**
 * Add a client daemon the owners list of an SRv6 SID.
 *
 * @param SID to which the owner needs to be added
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @return True if success, False otherwise
 */
bool zebra_srv6_sid_owner_add(struct zebra_srv6_sid *sid, uint8_t proto,
			      unsigned short instance)
{
	struct zebra_srv6_sid_owner *owner;

	if (!sid)
		return false;

	owner = XCALLOC(MTYPE_ZEBRA_SRV6_SID_OWNER,
			sizeof(struct zebra_srv6_sid_owner));
	owner->proto = proto;
	owner->instance = instance;

	listnode_add(sid->owners, owner);

	return true;
}

/**
 * Remove a client daemon from the owners list of an SRv6 SID.
 *
 * @param SID to which the owner needs to be removed
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @return True if success, False otherwise
 */
bool zebra_srv6_sid_owner_del(struct zebra_srv6_sid *sid, uint8_t proto,
			      unsigned short instance, uint32_t session_id)
{
	struct zebra_srv6_sid_owner *owner;
	struct listnode *node, *nnode;

	if (!sid)
		return false;

	for (ALL_LIST_ELEMENTS(sid->owners, node, nnode, owner)) {
		if (owner->proto == proto && owner->instance == instance) {
			listnode_delete(sid->owners, owner);
			zebra_srv6_sid_owner_free(owner);
		}
	}

	return true;
}

/* --- Zebra SRv6 SID context management functions -------------------------- */

struct zebra_srv6_sid_ctx *zebra_srv6_sid_ctx_alloc(void)
{
	struct zebra_srv6_sid_ctx *ctx = NULL;

	ctx = XCALLOC(MTYPE_ZEBRA_SRV6_SID_CTX,
		      sizeof(struct zebra_srv6_sid_ctx));

	return ctx;
}

void zebra_srv6_sid_ctx_free(struct zebra_srv6_sid_ctx *ctx)
{
	XFREE(MTYPE_ZEBRA_SRV6_SID_CTX, ctx);
}

/**
 * Free an SRv6 SID context.
 *
 * @param val SRv6 SID context to be freed
 */
void delete_zebra_srv6_sid_ctx(void *val)
{
	zebra_srv6_sid_ctx_free((struct zebra_srv6_sid_ctx *)val);
}

/* --- Zebra SRv6 SID format management functions --------------------------- */

struct zebra_srv6_sid_format *zebra_srv6_sid_format_alloc(const char *name)
{
	struct zebra_srv6_sid_format *format = NULL;

	format = XCALLOC(MTYPE_ZEBRA_SRV6_SID_FORMAT,
			 sizeof(struct zebra_srv6_sid_format));
	strlcpy(format->name, name, sizeof(format->name));

	QOBJ_REG(format, zebra_srv6_sid_format);
	return format;
}

void zebra_srv6_sid_format_free(struct zebra_srv6_sid_format *format)
{
	if (!format)
		return;

	QOBJ_UNREG(format);
	XFREE(MTYPE_ZEBRA_SRV6_SID_FORMAT, format);
}

/**
 * Free an SRv6 SID format.
 *
 * @param val SRv6 SID format to be freed
 */
void delete_zebra_srv6_sid_format(void *val)
{
	zebra_srv6_sid_format_free((struct zebra_srv6_sid_format *)val);
}

void zebra_srv6_sid_format_register(struct zebra_srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	/* Ensure that the format is registered only once */
	assert(!zebra_srv6_sid_format_lookup(format->name));

	listnode_add(srv6->sid_formats, format);
}

void zebra_srv6_sid_format_unregister(struct zebra_srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	listnode_delete(srv6->sid_formats, format);
}

struct zebra_srv6_sid_format *zebra_srv6_sid_format_lookup(const char *name)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_format *format;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->sid_formats, node, format))
		if (!strncmp(name, format->name, sizeof(format->name)))
			return format;

	return NULL;
}

/*
 * Called when a SID format is modified by the user.
 *
 * After modifying a SID format, the SIDs that are using that format may no
 * longer be valid.
 * This function walks through the list of locators that are using the SID format
 * and notifies the zclients that the locator has changed, so that the zclients
 * can withdraw/uninstall the old SIDs, allocate/program/advertise the new SIDs.
 */
void zebra_srv6_sid_format_changed_cb(struct zebra_srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_locator *locator;
	struct listnode *node;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: SID format %s has changed. Notifying zclients.",
			   __func__, format->name);

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator))
		if (locator->sid_format == format) {
			if (IS_ZEBRA_DEBUG_PACKET)
				zlog_debug("%s: Locator %s has changed because its format (%s) "
					"has been modified. Notifying zclients.",
					   __func__, locator->locator.name,
					   format->name);

			/* Notify zclients that the locator is no longer valid */
			zebra_notify_srv6_locator_delete(locator);

			/* Update the locator based on the new SID format */
			locator->locator.block_bits_length = format->block_len;
			locator->locator.node_bits_length = format->node_len;
			locator->locator.function_bits_length =
				format->function_len;
			locator->locator.argument_bits_length =
				format->argument_len;
			if (format->type ==
			    ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID)
				SET_FLAG(locator->locator.flags,
					 SRV6_LOCATOR_USID);
			else
				UNSET_FLAG(locator->locator.flags,
					   SRV6_LOCATOR_USID);

			/* Notify zclients about the updated locator */
			zebra_notify_srv6_locator_add(locator);
		}
}

/*
 * Helper function to create the SRv6 compressed format `usid-f3216`.
 */
static struct zebra_srv6_sid_format *create_srv6_sid_format_usid_f3216(void)
{
	struct zebra_srv6_sid_format *format = NULL;

	format = zebra_srv6_sid_format_alloc(
		ZEBRA_SRV6_SID_FORMAT_USID_F3216_NAME);

	format->type = ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID;

	/* Define block/node/function length */
	format->block_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_BLOCK_LEN;
	format->node_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_NODE_LEN;
	format->function_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_FUNCTION_LEN;
	format->argument_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_ARGUMENT_LEN;

	/* Define the ranges from which the function is allocated */
	format->config.usid.lib_start =
		ZEBRA_SRV6_SID_FORMAT_USID_F3216_LIB_START;
	format->config.usid.elib_start =
		ZEBRA_SRV6_SID_FORMAT_USID_F3216_ELIB_START;
	format->config.usid.elib_end = ZEBRA_SRV6_SID_FORMAT_USID_F3216_ELIB_END;
	format->config.usid.wlib_start =
		ZEBRA_SRV6_SID_FORMAT_USID_F3216_WLIB_START;
	format->config.usid.wlib_end = ZEBRA_SRV6_SID_FORMAT_USID_F3216_WLIB_END;
	format->config.usid.ewlib_start =
		ZEBRA_SRV6_SID_FORMAT_USID_F3216_EWLIB_START;

	return format;
}

/*
 * Helper function to create the SRv6 uncompressed format.
 */
static struct zebra_srv6_sid_format *create_srv6_sid_format_uncompressed(void)
{
	struct zebra_srv6_sid_format *format = NULL;

	format = zebra_srv6_sid_format_alloc(
		ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_NAME);

	format->type = ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED;

	/* Define block/node/function length */
	format->block_len = ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_BLOCK_LEN;
	format->node_len = ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_NODE_LEN;
	format->function_len = ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_FUNCTION_LEN;
	format->argument_len = ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_ARGUMENT_LEN;

	/* Define the ranges from which the function is allocated */
	format->config.uncompressed.explicit_start =
		ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_EXPLICIT_RANGE_START;

	return format;
}

/* --- Zebra SRv6 SID function management functions ---------------------------- */

uint32_t *zebra_srv6_sid_func_alloc(void)
{
	return XCALLOC(MTYPE_ZEBRA_SRV6_SID_FUNC, sizeof(uint32_t));
}

void zebra_srv6_sid_func_free(uint32_t *func)
{
	XFREE(MTYPE_ZEBRA_SRV6_SID_FUNC, func);
}

/**
 * Free an SRv6 SID function.
 *
 * @param val SRv6 SID function to be freed
 */
void delete_zebra_srv6_sid_func(void *val)
{
	zebra_srv6_sid_func_free((uint32_t *)val);
}

/* --- Zebra SRv6 SID block management functions ---------------------------- */

static struct zebra_srv6_sid_block *zebra_srv6_sid_block_alloc_internal(void)
{
	struct zebra_srv6_sid_block *block = NULL;

	block = XCALLOC(MTYPE_ZEBRA_SRV6_SID_BLOCK,
			sizeof(struct zebra_srv6_sid_block));

	return block;
}

struct zebra_srv6_sid_block *
zebra_srv6_sid_block_alloc(struct zebra_srv6_sid_format *format)
{
	struct zebra_srv6_sid_block *block;

	block = zebra_srv6_sid_block_alloc_internal();
	block->sid_format = format;

	if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID) {
		uint32_t wlib_start, wlib_end, func;

		/* Init uSID LIB */
		block->u.usid.lib.func_allocated = list_new();
		block->u.usid.lib.func_allocated->del =
			delete_zebra_srv6_sid_func;
		block->u.usid.lib.func_released = list_new();
		block->u.usid.lib.func_released->del =
			delete_zebra_srv6_sid_func;
		block->u.usid.lib.first_available_func =
			format->config.usid.lib_start;

		/* Init uSID Wide LIB */
		wlib_start = block->sid_format->config.usid.wlib_start;
		wlib_end = block->sid_format->config.usid.wlib_end;
		block->u.usid.wide_lib = XCALLOC(MTYPE_ZEBRA_SRV6_USID_WLIB,
						 (wlib_end - wlib_start +
						  1) * sizeof(struct wide_lib));
		for (func = 0; func < wlib_end - wlib_start + 1; func++) {
			block->u.usid.wide_lib[func].func_allocated = list_new();
			block->u.usid.wide_lib[func].func_allocated->del =
				delete_zebra_srv6_sid_func;
			block->u.usid.wide_lib[func].func_released = list_new();
			block->u.usid.wide_lib[func].func_released->del =
				delete_zebra_srv6_sid_func;
		}
	} else if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
		block->u.uncompressed.func_allocated = list_new();
		block->u.uncompressed.func_allocated->del =
			delete_zebra_srv6_sid_func;
		block->u.uncompressed.func_released = list_new();
		block->u.uncompressed.func_released->del =
			delete_zebra_srv6_sid_func;
		block->u.uncompressed.first_available_func =
			ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_FUNC_UNRESERVED_MIN;
	} else {
		/* We should never arrive here */
		assert(0);
	}

	return block;
}

void zebra_srv6_sid_block_free(struct zebra_srv6_sid_block *block)
{
	/*
	 * We expect the zebra_srv6_sid_block_free function to be called only
	 * when the block is no longer referenced by anyone
	 */
	assert(block->refcnt == 0);

	if (block->sid_format->type ==
	    ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID) {
		uint32_t wlib_start, wlib_end, func;

		/* Free uSID LIB */
		list_delete(&block->u.usid.lib.func_allocated);
		list_delete(&block->u.usid.lib.func_released);

		/* Free uSID Wide LIB */
		wlib_start = block->sid_format->config.usid.wlib_start;
		wlib_end = block->sid_format->config.usid.wlib_end;
		for (func = 0; func < wlib_end - wlib_start + 1; func++) {
			list_delete(
				&block->u.usid.wide_lib[func].func_allocated);
			list_delete(&block->u.usid.wide_lib[func].func_released);
		}
		XFREE(MTYPE_ZEBRA_SRV6_USID_WLIB, block->u.usid.wide_lib);
	} else if (block->sid_format->type ==
		   ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
		list_delete(&block->u.uncompressed.func_allocated);
		list_delete(&block->u.uncompressed.func_released);
	} else {
		/* We should never arrive here */
		assert(0);
	}

	XFREE(MTYPE_ZEBRA_SRV6_SID_BLOCK, block);
}

/**
 * Free an SRv6 SID block.
 *
 * @param val SRv6 SID block to be freed
 */
void delete_zebra_srv6_sid_block(void *val)
{
	zebra_srv6_sid_block_free((struct zebra_srv6_sid_block *)val);
}

struct zebra_srv6_sid_block *
zebra_srv6_sid_block_lookup(struct prefix_ipv6 *prefix)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_block *block;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->sid_blocks, node, block))
		if (prefix_match(prefix, &block->prefix))
			return block;

	return NULL;
}

/* --- Zebra SRv6 SID management functions ---------------------------------- */

/**
 * Alloc and fill an SRv6 SID.
 *
 * @param ctx Context associated with the SID to be created
 * @param sid_value IPv6 address associated with the SID to be created
 * @param locator Parent locator of the SID to be created
 * @param sid_block Block from which the SID value has been allocated
 * @param sid_func Function part of the SID to be created
 * @param alloc_mode Allocation mode of the Function (dynamic vs explicit)
 * @return The requested SID
 */
struct zebra_srv6_sid *
zebra_srv6_sid_alloc(struct zebra_srv6_sid_ctx *ctx, struct in6_addr *sid_value,
		     struct zebra_srv6_locator *locator,
		     struct zebra_srv6_sid_block *sid_block, uint32_t sid_func,
		     enum srv6_sid_alloc_mode alloc_mode)
{
	struct zebra_srv6_sid *sid;

	if (!ctx || !sid_value)
		return NULL;

	sid = XCALLOC(MTYPE_ZEBRA_SRV6_SID, sizeof(struct zebra_srv6_sid));
	sid->ctx = ctx;
	sid->value = *sid_value;
	sid->locator = locator;
	sid->block = sid_block;
	sid->func = sid_func;
	sid->alloc_mode = alloc_mode;
	sid->owners = list_new();
	sid->owners->del = delete_zebra_srv6_sid_owner;

	return sid;
}

void zebra_srv6_sid_free(struct zebra_srv6_sid *sid)
{
	list_delete(&sid->owners);
	XFREE(MTYPE_ZEBRA_SRV6_SID, sid);
}

/**
 * Free an SRv6 SID.
 *
 * @param val SRv6 SID to be freed
 */
void delete_zebra_srv6_sid(void *val)
{
	zebra_srv6_sid_free((struct zebra_srv6_sid *)val);
}

/* --- Zebra SRv6 locator management functions ------------------------------ */

struct zebra_srv6_locator *zebra_srv6_locator_alloc(const char *name)
{
	struct zebra_srv6_locator *locator = NULL;

	locator = XCALLOC(MTYPE_ZEBRA_SRV6_LOCATOR,
			  sizeof(struct zebra_srv6_locator));
	strlcpy(locator->locator.name, name, sizeof(locator->locator.name));
	locator->locator.chunks = list_new();
	locator->locator.chunks->del = srv6_locator_chunk_list_free;

	QOBJ_REG(locator, zebra_srv6_locator);
	return locator;
}

void zebra_srv6_locator_free(struct zebra_srv6_locator *locator)
{
	if (!locator)
		return;

	QOBJ_UNREG(locator);
	list_delete(&locator->locator.chunks);
	XFREE(MTYPE_ZEBRA_SRV6_LOCATOR, locator);
}

void zebra_srv6_locator_add(struct zebra_srv6_locator *locator)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_locator *tmp;
	struct listnode *node;
	struct zserv *client;

	tmp = zebra_srv6_locator_lookup(locator->locator.name);
	if (!tmp)
		listnode_add(srv6->locators, locator);

	/*
	 * Notify new locator info to zclients.
	 *
	 * The srv6 locators and their prefixes are managed by zserv(zebra).
	 * And an actual configuration the srv6 sid in the srv6 locator is done
	 * by zclient(bgpd, isisd, etc). The configuration of each locator
	 * allocation and specify it by zserv and zclient should be
	 * asynchronous. For that, zclient should be received the event via
	 * ZAPI when a srv6 locator is added on zebra.
	 * Basically, in SRv6, adding/removing SRv6 locators is performed less
	 * frequently than adding rib entries, so a broad to all zclients will
	 * not degrade the overall performance of FRRouting.
	 */
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client))
		zsend_zebra_srv6_locator_add(client, &locator->locator);
}

void zebra_srv6_locator_delete(struct zebra_srv6_locator *locator)
{
	struct listnode *n;
	struct srv6_locator_chunk *c;
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zserv *client;

	/*
	 * Notify deleted locator info to zclients if needed.
	 *
	 * zclient(bgpd,isisd,etc) allocates a sid from srv6 locator chunk and
	 * uses it for its own purpose. For example, in the case of BGP L3VPN,
	 * the SID assigned to vpn unicast rib will be given.
	 * And when the locator is deleted by zserv(zebra), those SIDs need to
	 * be withdrawn. The zclient must initiate the withdrawal of the SIDs
	 * by ZEBRA_SRV6_LOCATOR_DELETE, and this notification is sent to the
	 * owner of each chunk.
	 */
	for (ALL_LIST_ELEMENTS_RO((struct list *)locator->locator.chunks, n, c)) {
		if (c->proto == ZEBRA_ROUTE_SYSTEM)
			continue;
		client = zserv_find_client(c->proto, c->instance);
		if (!client) {
			zlog_warn(
				"%s: Not found zclient(proto=%u, instance=%u).",
				__func__, c->proto, c->instance);
			continue;
		}
		zsend_zebra_srv6_locator_delete(client, &locator->locator);
	}

	listnode_delete(srv6->locators, locator);
	zebra_srv6_locator_free(locator);
}

struct zebra_srv6_locator *zebra_srv6_locator_lookup(const char *name)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_locator *locator;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator))
		if (!strncmp(name, locator->locator.name, SRV6_LOCNAME_SIZE))
			return locator;
	return NULL;
}

void zebra_notify_srv6_locator_add(struct zebra_srv6_locator *locator)
{
	struct listnode *node;
	struct zserv *client;

	/*
	 * Notify new locator info to zclients.
	 *
	 * The srv6 locators and their prefixes are managed by zserv(zebra).
	 * And an actual configuration the srv6 sid in the srv6 locator is done
	 * by zclient(bgpd, isisd, etc). The configuration of each locator
	 * allocation and specify it by zserv and zclient should be
	 * asynchronous. For that, zclient should be received the event via
	 * ZAPI when a srv6 locator is added on zebra.
	 * Basically, in SRv6, adding/removing SRv6 locators is performed less
	 * frequently than adding rib entries, so a broad to all zclients will
	 * not degrade the overall performance of FRRouting.
	 */
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client))
		zsend_zebra_srv6_locator_add(client, &locator->locator);
}

void zebra_notify_srv6_locator_delete(struct zebra_srv6_locator *locator)
{
	struct listnode *n;
	struct srv6_locator_chunk *c;
	struct zserv *client;

	/*
	 * Notify deleted locator info to zclients if needed.
	 *
	 * zclient(bgpd,isisd,etc) allocates a sid from srv6 locator chunk and
	 * uses it for its own purpose. For example, in the case of BGP L3VPN,
	 * the SID assigned to vpn unicast rib will be given.
	 * And when the locator is deleted by zserv(zebra), those SIDs need to
	 * be withdrawn. The zclient must initiate the withdrawal of the SIDs
	 * by ZEBRA_SRV6_LOCATOR_DELETE, and this notification is sent to the
	 * owner of each chunk.
	 */
	for (ALL_LIST_ELEMENTS_RO((struct list *)locator->locator.chunks, n, c)) {
		if (c->proto == ZEBRA_ROUTE_SYSTEM)
			continue;
		client = zserv_find_client(c->proto, c->instance);
		if (!client) {
			zlog_warn("Not found zclient(proto=%u, instance=%u).",
				  c->proto, c->instance);
			continue;
		}
		zsend_zebra_srv6_locator_delete(client, &locator->locator);
	}
}

struct zebra_srv6 srv6;

struct zebra_srv6 *zebra_srv6_get_default(void)
{
	static bool first_execution = true;
	struct zebra_srv6_sid_format *format_usidf3216;
	struct zebra_srv6_sid_format *format_uncompressed;

	if (first_execution) {
		first_execution = false;
		srv6.locators = list_new();

		/* Initialize list of SID formats */
		srv6.sid_formats = list_new();
		srv6.sid_formats->del = delete_zebra_srv6_sid_format;

		/* Create SID format `usid-f3216` */
		format_usidf3216 = create_srv6_sid_format_usid_f3216();
		zebra_srv6_sid_format_register(format_usidf3216);

		/* Create SID format `uncompressed` */
		format_uncompressed = create_srv6_sid_format_uncompressed();
		zebra_srv6_sid_format_register(format_uncompressed);

		/* Init list to store SRv6 SIDs */
		srv6.sids = list_new();
		srv6.sids->del = delete_zebra_srv6_sid_ctx;

		/* Init list to store SRv6 SID blocks */
		srv6.sid_blocks = list_new();
		srv6.sid_blocks->del = delete_zebra_srv6_sid_block;
	}
	return &srv6;
}

/**
 * Core function, assigns srv6-locator chunks
 *
 * It first searches through the list to check if there's one available
 * (previously released). Otherwise it creates and assigns a new one
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id SessionID of client
 * @param name Name of SRv6-locator
 * @return Pointer to the assigned srv6-locator chunk,
 *         or NULL if the request could not be satisfied
 */
static struct srv6_locator *
assign_srv6_locator_chunk(uint8_t proto,
			  uint16_t instance,
			  uint32_t session_id,
			  const char *locator_name)
{
	bool chunk_found = false;
	struct listnode *node = NULL;
	struct zebra_srv6_locator *loc = NULL;
	struct srv6_locator_chunk *chunk = NULL;

	loc = zebra_srv6_locator_lookup(locator_name);
	if (!loc) {
		zlog_info("%s: locator %s was not found",
			  __func__, locator_name);
		return NULL;
	}

	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->locator.chunks, node,
				  chunk)) {
		if (chunk->proto != NO_PROTO && chunk->proto != proto)
			continue;
		chunk_found = true;
		break;
	}

	if (!chunk_found) {
		zlog_info("%s: locator is already owned", __func__);
		return NULL;
	}

	chunk->proto = proto;
	chunk->instance = instance;
	chunk->session_id = session_id;
	return &loc->locator;
}

static int zebra_srv6_manager_get_locator_chunk(struct srv6_locator **loc,
						struct zserv *client,
						const char *locator_name,
						vrf_id_t vrf_id)
{
	int ret = 0;

	*loc = assign_srv6_locator_chunk(client->proto, client->instance,
					 client->session_id, locator_name);

	if (!*loc)
		zlog_err("Unable to assign locator chunk to %s instance %u",
			 zebra_route_string(client->proto), client->instance);
	else if (IS_ZEBRA_DEBUG_PACKET)
		zlog_info("Assigned locator chunk %s to %s instance %u",
			  (*loc)->name, zebra_route_string(client->proto),
			  client->instance);

	if (*loc && (*loc)->status_up)
		ret = zsend_srv6_manager_get_locator_chunk_response(client,
								    vrf_id,
								    *loc);
	return ret;
}

/**
 * Core function, release no longer used srv6-locator chunks
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id Zclient session ID, to identify the zclient session
 * @param locator_name SRv6-locator name, to identify the actual locator
 * @return 0 on success, -1 otherwise
 */
static int release_srv6_locator_chunk(uint8_t proto, uint16_t instance,
				      uint32_t session_id,
				      const char *locator_name)
{
	int ret = -1;
	struct listnode *node;
	struct srv6_locator_chunk *chunk;
	struct zebra_srv6_locator *loc = NULL;

	loc = zebra_srv6_locator_lookup(locator_name);
	if (!loc)
		return -1;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Releasing srv6-locator on %s", __func__,
			   locator_name);

	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->locator.chunks, node,
				  chunk)) {
		if (chunk->proto != proto ||
		    chunk->instance != instance ||
		    chunk->session_id != session_id)
			continue;
		chunk->proto = NO_PROTO;
		chunk->instance = 0;
		chunk->session_id = 0;
		chunk->keep = 0;
		ret = 0;
		break;
	}

	if (ret != 0)
		flog_err(EC_ZEBRA_SRV6M_UNRELEASED_LOCATOR_CHUNK,
			 "%s: SRv6 locator chunk not released", __func__);

	return ret;
}

static int zebra_srv6_manager_release_locator_chunk(struct zserv *client,
						    const char *locator_name,
						    vrf_id_t vrf_id)
{
	if (vrf_id != VRF_DEFAULT) {
		zlog_err("SRv6 locator doesn't support vrf");
		return -1;
	}

	return release_srv6_locator_chunk(client->proto, client->instance,
					  client->session_id, locator_name);
}

/**
 * Release srv6-locator chunks from a client.
 *
 * Called on client disconnection or reconnection. It only releases chunks
 * with empty keep value.
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @return Number of chunks released
 */
int release_daemon_srv6_locator_chunks(struct zserv *client)
{
	int ret;
	int count = 0;
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *loc_node;
	struct listnode *chunk_node;
	struct srv6_locator *loc;
	struct srv6_locator_chunk *chunk;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Releasing chunks for client proto %s, instance %d, session %u",
			   __func__, zebra_route_string(client->proto),
			   client->instance, client->session_id);

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, loc_node, loc)) {
		for (ALL_LIST_ELEMENTS_RO(loc->chunks, chunk_node, chunk)) {
			if (chunk->proto == client->proto &&
			    chunk->instance == client->instance &&
			    chunk->session_id == client->session_id &&
			    chunk->keep == 0) {
				ret = release_srv6_locator_chunk(
						chunk->proto, chunk->instance,
						chunk->session_id, loc->name);
				if (ret == 0)
					count++;
			}
		}
	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Released %d srv6-locator chunks",
			   __func__, count);

	return count;
}

void zebra_srv6_encap_src_addr_set(struct in6_addr *encap_src_addr)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	if (!encap_src_addr)
		return;

	memcpy(&srv6->encap_src_addr, encap_src_addr, sizeof(struct in6_addr));
}

void zebra_srv6_encap_src_addr_unset(void)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	memset(&srv6->encap_src_addr, 0, sizeof(struct in6_addr));
}

void zebra_srv6_terminate(void)
{
	struct zebra_srv6_locator *locator;
	struct zebra_srv6_sid_format *format;
	struct zebra_srv6_sid_block *block;
	struct zebra_srv6_sid_ctx *sid_ctx;

	if (srv6.locators) {
		while (listcount(srv6.locators)) {
			locator = listnode_head(srv6.locators);

			listnode_delete(srv6.locators, locator);
			zebra_srv6_locator_free(locator);
		}

		list_delete(&srv6.locators);
	}

	/* Free SRv6 SID formats */
	if (srv6.sid_formats) {
		while (listcount(srv6.sid_formats)) {
			format = listnode_head(srv6.sid_formats);

			zebra_srv6_sid_format_unregister(format);
			zebra_srv6_sid_format_free(format);
		}

		list_delete(&srv6.sid_formats);
	}

	/* Free SRv6 SIDs */
	if (srv6.sids) {
		while (listcount(srv6.sids)) {
			sid_ctx = listnode_head(srv6.sids);

			listnode_delete(srv6.sids, sid_ctx);
			zebra_srv6_sid_ctx_free(sid_ctx);
		}

		list_delete(&srv6.sids);
	}

	/* Free SRv6 SID blocks */
	if (srv6.sid_blocks) {
		while (listcount(srv6.sid_blocks)) {
			block = listnode_head(srv6.sid_blocks);

			listnode_delete(srv6.sid_blocks, block);
			zebra_srv6_sid_block_free(block);
		}

		list_delete(&srv6.sid_blocks);
	}
}

void zebra_srv6_init(void)
{
	hook_register(zserv_client_close, zebra_srv6_cleanup);
	hook_register(srv6_manager_get_chunk,
		      zebra_srv6_manager_get_locator_chunk);
	hook_register(srv6_manager_release_chunk,
		      zebra_srv6_manager_release_locator_chunk);
}

bool zebra_srv6_is_enable(void)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	return listcount(srv6->locators);
}
