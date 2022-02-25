/*
 * Zebra connect code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"
#include "nexthop_group.h"

#include "pbr_nht.h"
#include "pbr_map.h"
#include "pbr_memory.h"
#include "pbr_zebra.h"
#include "pbr_debug.h"
#include "pbr_vrf.h"

DEFINE_MTYPE_STATIC(PBRD, PBR_INTERFACE, "PBR Interface");

/* Zebra structure to hold current status. */
struct zclient *zclient;

struct pbr_interface *pbr_if_new(struct interface *ifp)
{
	struct pbr_interface *pbr_ifp;

	assert(ifp);
	assert(!ifp->info);

	pbr_ifp = XCALLOC(MTYPE_PBR_INTERFACE, sizeof(*pbr_ifp));

	ifp->info = pbr_ifp;
	return pbr_ifp;
}

void pbr_if_del(struct interface *ifp)
{
	XFREE(MTYPE_PBR_INTERFACE, ifp->info);
}

/* Interface addition message from zebra. */
int pbr_ifp_create(struct interface *ifp)
{
	DEBUGD(&pbr_dbg_zebra, "%s", ifp->name);

	if (!ifp->info)
		pbr_if_new(ifp);

	pbr_nht_interface_update(ifp);
	/* Update nexthops tracked from a `set nexthop` command */
	pbr_nht_nexthop_interface_update(ifp);

	pbr_map_policy_interface_update(ifp, true);

	return 0;
}

int pbr_ifp_destroy(struct interface *ifp)
{
	DEBUGD(&pbr_dbg_zebra, "%s", ifp->name);

	pbr_map_policy_interface_update(ifp, false);

	return 0;
}

static int interface_address_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;
	char buf[PREFIX_STRLEN];

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	DEBUGD(&pbr_dbg_zebra, "%s added %s", c ? c->ifp->name : "Unknown",
	       c ? prefix2str(c->address, buf, sizeof(buf)) : "Unknown");

	return 0;
}

static int interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	DEBUGD(&pbr_dbg_zebra, "%s deleted %pFX", c->ifp->name, c->address);

	connected_free(&c);
	return 0;
}

int pbr_ifp_up(struct interface *ifp)
{
	DEBUGD(&pbr_dbg_zebra, "%s is up", ifp->name);

	pbr_nht_nexthop_interface_update(ifp);

	return 0;
}

int pbr_ifp_down(struct interface *ifp)
{
	DEBUGD(&pbr_dbg_zebra, "%s is down", ifp->name);

	pbr_nht_nexthop_interface_update(ifp);

	return 0;
}

static int interface_vrf_update(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	vrf_id_t new_vrf_id;

	ifp = zebra_interface_vrf_update_read(zclient->ibuf, vrf_id,
					      &new_vrf_id);

	if (!ifp) {
		DEBUGD(&pbr_dbg_zebra, "VRF change interface not found");

		return 0;
	}

	DEBUGD(&pbr_dbg_zebra, "%s VRF change %u -> %u", ifp->name, vrf_id,
	       new_vrf_id);

	if_update_to_new_vrf(ifp, new_vrf_id);

	return 0;
}

static int route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table_id;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table_id, &note,
				      NULL, NULL))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_FAIL_INSTALL:
		DEBUGD(&pbr_dbg_zebra,
		       "[%pFX] Route install failure for table: %u", &p,
		       table_id);
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		DEBUGD(&pbr_dbg_zebra,
		       "[%pFX] Route better admin distance won for table: %u",
		       &p, table_id);
		break;
	case ZAPI_ROUTE_INSTALLED:
		DEBUGD(&pbr_dbg_zebra,
		       "[%pFX] Route installed succeeded for table: %u", &p,
		       table_id);
		pbr_nht_route_installed_for_table(table_id);
		break;
	case ZAPI_ROUTE_REMOVED:
		DEBUGD(&pbr_dbg_zebra,
		       "[%pFX] Route Removed succeeded for table: %u", &p,
		       table_id);
		pbr_nht_route_removed_for_table(table_id);
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		DEBUGD(&pbr_dbg_zebra, "[%pFX] Route remove fail for table: %u",
		       &p, table_id);
		break;
	}

	return 0;
}

static int rule_notify_owner(ZAPI_CALLBACK_ARGS)
{
	uint32_t seqno, priority, unique;
	enum zapi_rule_notify_owner note;
	struct pbr_map_sequence *pbrms;
	struct pbr_map_interface *pmi;
	char ifname[INTERFACE_NAMSIZ + 1];
	uint64_t installed;

	if (!zapi_rule_notify_decode(zclient->ibuf, &seqno, &priority, &unique,
				     ifname, &note))
		return -1;

	pmi = NULL;
	pbrms = pbrms_lookup_unique(unique, ifname, &pmi);
	if (!pbrms) {
		DEBUGD(&pbr_dbg_zebra, "Failure to lookup pbrms based upon %u",
		       unique);
		return 0;
	}

	installed = 1 << pmi->install_bit;

	switch (note) {
	case ZAPI_RULE_FAIL_INSTALL:
		pbrms->installed &= ~installed;
		break;
	case ZAPI_RULE_INSTALLED:
		pbrms->installed |= installed;
		break;
	case ZAPI_RULE_FAIL_REMOVE:
		/* Don't change state on rule removal failure */
		break;
	case ZAPI_RULE_REMOVED:
		pbrms->installed &= ~installed;
		break;
	}

	DEBUGD(&pbr_dbg_zebra, "Received %s: %" PRIu64,
	       zapi_rule_notify_owner2str(note), pbrms->installed);

	pbr_map_final_interface_deletion(pbrms->parent, pmi);

	return 0;
}

static void zebra_connected(struct zclient *zclient)
{
	DEBUGD(&pbr_dbg_zebra, "Registering for fun and profit");
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

static void route_add_helper(struct zapi_route *api, struct nexthop_group nhg,
			     uint8_t install_afi)
{
	struct zapi_nexthop *api_nh;
	struct nexthop *nhop;
	int i;

	api->prefix.family = install_afi;

	DEBUGD(&pbr_dbg_zebra, "    Encoding %pFX", &api->prefix);

	i = 0;
	for (ALL_NEXTHOPS(nhg, nhop)) {
		api_nh = &api->nexthops[i];
		api_nh->vrf_id = nhop->vrf_id;
		api_nh->type = nhop->type;
		api_nh->weight = nhop->weight;
		switch (nhop->type) {
		case NEXTHOP_TYPE_IPV4:
			api_nh->gate.ipv4 = nhop->gate.ipv4;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			api_nh->gate.ipv4 = nhop->gate.ipv4;
			api_nh->ifindex = nhop->ifindex;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			api_nh->ifindex = nhop->ifindex;
			break;
		case NEXTHOP_TYPE_IPV6:
			memcpy(&api_nh->gate.ipv6, &nhop->gate.ipv6,
			       IPV6_MAX_BYTELEN);
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			api_nh->ifindex = nhop->ifindex;
			memcpy(&api_nh->gate.ipv6, &nhop->gate.ipv6,
			       IPV6_MAX_BYTELEN);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			api_nh->bh_type = nhop->bh_type;
			break;
		}
		i++;
	}
	api->nexthop_num = i;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, api);
}

/*
 * This function assumes a default route is being
 * installed into the appropriate tableid
 */
void route_add(struct pbr_nexthop_group_cache *pnhgc, struct nexthop_group nhg,
	       afi_t install_afi)
{
	struct zapi_route api;

	DEBUGD(&pbr_dbg_zebra, "for Table: %d", pnhgc->table_id);

	memset(&api, 0, sizeof(api));

	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_PBR;
	api.safi = SAFI_UNICAST;
	/*
	 * Sending a default route
	 */
	api.tableid = pnhgc->table_id;
	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	switch (install_afi) {
	case AFI_MAX:
		route_add_helper(&api, nhg, AF_INET);
		route_add_helper(&api, nhg, AF_INET6);
		break;
	case AFI_IP:
		route_add_helper(&api, nhg, AF_INET);
		break;
	case AFI_IP6:
		route_add_helper(&api, nhg, AF_INET6);
		break;
	case AFI_L2VPN:
		DEBUGD(&pbr_dbg_zebra,
		       "Asked to install unsupported route type: L2VPN");
		break;
	case AFI_UNSPEC:
		DEBUGD(&pbr_dbg_zebra,
		       "Asked to install unspecified route type");
		break;
	}
}

/*
 * This function assumes a default route is being
 * removed from the appropriate tableid
 */
void route_delete(struct pbr_nexthop_group_cache *pnhgc, afi_t afi)
{
	struct zapi_route api;

	DEBUGD(&pbr_dbg_zebra, "for Table: %d", pnhgc->table_id);

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_PBR;
	api.safi = SAFI_UNICAST;

	api.tableid = pnhgc->table_id;
	SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);

	switch (afi) {
	case AFI_IP:
		api.prefix.family = AF_INET;
		zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
		break;
	case AFI_IP6:
		api.prefix.family = AF_INET6;
		zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
		break;
	case AFI_MAX:
		api.prefix.family = AF_INET;
		zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
		api.prefix.family = AF_INET6;
		zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
		break;
	case AFI_L2VPN:
		DEBUGD(&pbr_dbg_zebra,
		       "Asked to delete unsupported route type: L2VPN");
		break;
	case AFI_UNSPEC:
		DEBUGD(&pbr_dbg_zebra,
		       "Asked to delete unspecified route type");
		break;
	}
}

static int pbr_zebra_nexthop_update(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route nhr;
	struct prefix matched;
	uint32_t i;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &matched, &nhr)) {
		zlog_err("Failure to decode Nexthop update message");
		return 0;
	}

	if (DEBUG_MODE_CHECK(&pbr_dbg_zebra, DEBUG_MODE_ALL)) {

		DEBUGD(&pbr_dbg_zebra,
		       "Received Nexthop update: %pFX against %pFX", &matched,
		       &nhr.prefix);

		DEBUGD(&pbr_dbg_zebra, "(Nexthops(%u)", nhr.nexthop_num);

		for (i = 0; i < nhr.nexthop_num; i++) {
			DEBUGD(&pbr_dbg_zebra,
			       "Type: %d: vrf: %d, ifindex: %d gate: %pI4",
			       nhr.nexthops[i].type, nhr.nexthops[i].vrf_id,
			       nhr.nexthops[i].ifindex,
			       &nhr.nexthops[i].gate.ipv4);
		}
	}

	nhr.prefix = matched;
	pbr_nht_nexthop_update(&nhr);
	return 1;
}

extern struct zebra_privs_t pbr_privs;

static zclient_handler *const pbr_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = interface_address_delete,
	[ZEBRA_INTERFACE_VRF_UPDATE] = interface_vrf_update,
	[ZEBRA_ROUTE_NOTIFY_OWNER] = route_notify_owner,
	[ZEBRA_RULE_NOTIFY_OWNER] = rule_notify_owner,
	[ZEBRA_NEXTHOP_UPDATE] = pbr_zebra_nexthop_update,
};

void pbr_zebra_init(void)
{
	struct zclient_options opt = { .receive_notify = true };

	zclient = zclient_new(master, &opt, pbr_handlers,
			      array_size(pbr_handlers));

	zclient_init(zclient, ZEBRA_ROUTE_PBR, 0, &pbr_privs);
	zclient->zebra_connected = zebra_connected;
}

void pbr_send_rnh(struct nexthop *nhop, bool reg)
{
	uint32_t command;
	struct prefix p;

	command = (reg) ?
		ZEBRA_NEXTHOP_REGISTER : ZEBRA_NEXTHOP_UNREGISTER;

	memset(&p, 0, sizeof(p));
	switch (nhop->type) {
	case NEXTHOP_TYPE_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		return;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		p.family = AF_INET;
		p.u.prefix4.s_addr = nhop->gate.ipv4.s_addr;
		p.prefixlen = IPV4_MAX_BITLEN;
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		p.family = AF_INET6;
		memcpy(&p.u.prefix6, &nhop->gate.ipv6, IPV6_MAX_BYTELEN);
		p.prefixlen = IPV6_MAX_BITLEN;
		if (IN6_IS_ADDR_LINKLOCAL(&nhop->gate.ipv6))
			/*
			 * Don't bother tracking link locals, just track their
			 * interface state.
			 */
			return;
		break;
	}

	if (zclient_send_rnh(zclient, command, &p, SAFI_UNICAST, false, false,
			     nhop->vrf_id)
	    == ZCLIENT_SEND_FAILURE) {
		zlog_warn("%s: Failure to send nexthop to zebra", __func__);
	}
}

static void pbr_encode_pbr_map_sequence_prefix(struct stream *s,
					       struct prefix *p,
					       unsigned char  family)
{
	struct prefix any;

	if (!p) {
		memset(&any, 0, sizeof(any));
		any.family = family;
		p = &any;
	}

	stream_putc(s, p->family);
	stream_putc(s, p->prefixlen);
	stream_put(s, &p->u.prefix, prefix_blen(p));
}

static void
pbr_encode_pbr_map_sequence_vrf(struct stream *s,
				const struct pbr_map_sequence *pbrms,
				const struct interface *ifp)
{
	struct pbr_vrf *pbr_vrf;

	if (pbrms->vrf_unchanged)
		pbr_vrf = ifp->vrf->info;
	else
		pbr_vrf = pbr_vrf_lookup_by_name(pbrms->vrf_name);

	if (!pbr_vrf) {
		DEBUGD(&pbr_dbg_zebra, "VRF not found");
		return;
	}

	stream_putl(s, pbr_vrf->vrf->data.l.table_id);
}

static void pbr_encode_pbr_map_sequence(struct stream *s,
					struct pbr_map_sequence *pbrms,
					struct interface *ifp)
{
	unsigned char family;

	family = AF_INET;
	if (pbrms->family)
		family = pbrms->family;

	stream_putl(s, pbrms->seqno);
	stream_putl(s, pbrms->ruleno);
	stream_putl(s, pbrms->unique);
	stream_putc(s, pbrms->ip_proto); /* The ip_proto */
	pbr_encode_pbr_map_sequence_prefix(s, pbrms->src, family);
	stream_putw(s, pbrms->src_prt);
	pbr_encode_pbr_map_sequence_prefix(s, pbrms->dst, family);
	stream_putw(s, pbrms->dst_prt);
	stream_putc(s, pbrms->dsfield);
	stream_putl(s, pbrms->mark);

	stream_putl(s, pbrms->action_queue_id);

	stream_putw(s, pbrms->action_vlan_id);
	stream_putw(s, pbrms->action_vlan_flags);
	stream_putw(s, pbrms->action_pcp);

	if (pbrms->vrf_unchanged || pbrms->vrf_lookup)
		pbr_encode_pbr_map_sequence_vrf(s, pbrms, ifp);
	else if (pbrms->nhgrp_name)
		stream_putl(s, pbr_nht_get_table(pbrms->nhgrp_name));
	else if (pbrms->nhg)
		stream_putl(s, pbr_nht_get_table(pbrms->internal_nhg_name));
	stream_put(s, ifp->name, INTERFACE_NAMSIZ);
}

bool pbr_send_pbr_map(struct pbr_map_sequence *pbrms,
		      struct pbr_map_interface *pmi, bool install, bool changed)
{
	struct pbr_map *pbrm = pbrms->parent;
	struct stream *s;
	uint64_t is_installed = (uint64_t)1 << pmi->install_bit;

	is_installed &= pbrms->installed;

	DEBUGD(&pbr_dbg_zebra, "for %s %d(%" PRIu64 ")", pbrm->name, install,
	       is_installed);

	/*
	 * If we are installed and asked to do so again and the config
	 * has not changed, just return.
	 *
	 * If we are not installed and asked
	 * to delete just return.
	 */
	if (install && is_installed && !changed)
		return false;

	if (!install && !is_installed)
		return false;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s,
			      install ? ZEBRA_RULE_ADD : ZEBRA_RULE_DELETE,
			      VRF_DEFAULT);

	/*
	 * We are sending one item at a time at the moment
	 */
	stream_putl(s, 1);

	DEBUGD(&pbr_dbg_zebra, "%s %s seq %u %d %s %u",
	       install ? "Installing" : "Deleting", pbrm->name, pbrms->seqno,
	       install, pmi->ifp->name, pmi->delete);

	pbr_encode_pbr_map_sequence(s, pbrms, pmi->ifp);

	stream_putw_at(s, 0, stream_get_endp(s));

	zclient_send_message(zclient);

	return true;
}
