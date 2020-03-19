/* NHRP daemon internal structures and function prototypes
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef NHRPD_H
#define NHRPD_H

#include "list.h"

#include "zbuf.h"
#include "zclient.h"
#include "qobj.h"
#include "debug.h"
#include "memory.h"
#include "resolver.h"

DECLARE_MGROUP(NHRPD);

#define NHRPD_DEFAULT_HOLDTIME	7200

#define NHRP_VTY_PORT		2610
#define NHRP_DEFAULT_CONFIG	"nhrpd.conf"

extern struct thread_master *master;

enum { NHRP_OK = 0,
       NHRP_ERR_FAIL,
       NHRP_ERR_NO_MEMORY,
       NHRP_ERR_UNSUPPORTED_INTERFACE,
       NHRP_ERR_NHRP_NOT_ENABLED,
       NHRP_ERR_ENTRY_EXISTS,
       NHRP_ERR_ENTRY_NOT_FOUND,
       NHRP_ERR_PROTOCOL_ADDRESS_MISMATCH,
       __NHRP_ERR_MAX };
#define NHRP_ERR_MAX		(__NHRP_ERR_MAX - 1)

struct notifier_block;

typedef void (*notifier_fn_t)(struct notifier_block *, unsigned long);

struct notifier_block {
	struct list_head notifier_entry;
	notifier_fn_t action;
};

struct notifier_list {
	struct list_head notifier_head;
};

#define NOTIFIER_LIST_INITIALIZER(l)                                           \
	{                                                                      \
		.notifier_head = LIST_INITIALIZER((l)->notifier_head)          \
	}

static inline void notifier_init(struct notifier_list *l)
{
	list_init(&l->notifier_head);
}

static inline void notifier_add(struct notifier_block *n,
				struct notifier_list *l, notifier_fn_t action)
{
	n->action = action;
	list_add_tail(&n->notifier_entry, &l->notifier_head);
}

static inline void notifier_del(struct notifier_block *n)
{
	list_del(&n->notifier_entry);
}

static inline void notifier_call(struct notifier_list *l, int cmd)
{
	struct notifier_block *n, *nn;
	list_for_each_entry_safe(n, nn, &l->notifier_head, notifier_entry) {
		n->action(n, cmd);
	}
}

static inline int notifier_active(struct notifier_list *l)
{
	return !list_empty(&l->notifier_head);
}

struct nhrp_vrf {
	char *vrfname;
	vrf_id_t vrf_id;
	char *nhrp_event_socket_path;
	int netlink_nflog_group;
	int netlink_mcast_nflog_group;
	/* operational contexts */
	int netlink_log_fd;
	int netlink_mcast_log_fd;
	struct thread *netlink_log_thread;
	struct thread *netlink_mcast_log_thread;
	struct event_manager *evmgr_connection;
	struct nhrp_reqid_pool *nhrp_event_reqid;

	struct route_table *zebra_rib[AFI_MAX];
	struct route_table *shortcut_rib[AFI_MAX];

	struct nhrp_reqid_pool *nhrp_packet_reqid;
	struct vici_conn *vici_connection;
	struct hash *vici_hash;

	struct hash *nhrp_vc_hash;
	struct list_head childlist_head[512];
	struct hash *nhrp_gre_list;
	int nhrp_socket_fd;

	QOBJ_FIELDS;
};

void nhrp_zebra_init(void);
void nhrp_zebra_register_log(vrf_id_t vrf_id, int group, bool reg);
void nhrp_route_init(struct nhrp_vrf *nhrp_vrf);
void nhrp_zebra_terminate(struct nhrp_vrf *nhrp_vrf);
void nhrp_zebra_terminate_zclient(void);
void nhrp_send_zebra_configure_arp(struct interface *ifp, int family);
void nhrp_send_zebra_nbr(union sockunion *in,
			 union sockunion *out,
			 struct interface *ifp);

void nhrp_send_zebra_gre_source_set(struct interface *ifp,
				    unsigned int link_idx,
				    vrf_id_t link_vrf_id);

extern int nhrp_send_zebra_gre_request(struct interface *ifp);
extern struct nhrp_gre_info *nhrp_gre_info_alloc(struct nhrp_gre_info *p,
						 struct nhrp_vrf *nhrp_vrf);

void nhrp_send_zebra_interface_redirect(struct interface *ifp,
					int af);
struct zbuf;
struct nhrp_vc;
struct nhrp_cache;
struct nhrp_nhs;
struct nhrp_interface;

#define MAX_ID_LENGTH			64
#define MAX_CERT_LENGTH			2048

enum nhrp_notify_type {
	NOTIFY_INTERFACE_UP,
	NOTIFY_INTERFACE_DOWN,
	NOTIFY_INTERFACE_CHANGED,
	NOTIFY_INTERFACE_ADDRESS_CHANGED,
	NOTIFY_INTERFACE_NBMA_CHANGED,
	NOTIFY_INTERFACE_MTU_CHANGED,
	NOTIFY_INTERFACE_IPSEC_CHANGED,

	NOTIFY_VC_IPSEC_CHANGED,
	NOTIFY_VC_IPSEC_UPDATE_NBMA,

	NOTIFY_PEER_UP,
	NOTIFY_PEER_DOWN,
	NOTIFY_PEER_IFCONFIG_CHANGED,
	NOTIFY_PEER_MTU_CHANGED,
	NOTIFY_PEER_NBMA_CHANGING,

	NOTIFY_CACHE_UP,
	NOTIFY_CACHE_DOWN,
	NOTIFY_CACHE_DELETE,
	NOTIFY_CACHE_USED,
	NOTIFY_CACHE_BINDING_CHANGE,
};

struct nhrp_vc {
	struct notifier_list notifier_list;
	uint32_t ipsec;
	uint32_t ike_uniqueid;
	uint8_t updating;
	uint8_t abort_migration;

	struct nhrp_vc_peer {
		union sockunion nbma;
		char id[MAX_ID_LENGTH];
		uint16_t certlen;
		uint8_t cert[MAX_CERT_LENGTH];
	} local, remote;
	struct nhrp_vrf *nhrp_vrf;
};

enum nhrp_route_type {
	NHRP_ROUTE_BLACKHOLE,
	NHRP_ROUTE_LOCAL,
	NHRP_ROUTE_NBMA_NEXTHOP,
	NHRP_ROUTE_OFF_NBMA,
};

struct nhrp_peer {
	unsigned int ref;
	unsigned online : 1;
	unsigned requested : 1;
	unsigned fallback_requested : 1;
	unsigned prio : 1;
	struct notifier_list notifier_list;
	struct interface *ifp;
	struct nhrp_vc *vc;
	struct thread *t_fallback;
	struct notifier_block vc_notifier, ifp_notifier;
	struct thread *t_timer;
};

struct nhrp_packet_parser {
	struct interface *ifp;
	struct nhrp_afi_data *if_ad;
	struct nhrp_peer *peer;
	struct zbuf *pkt;
	struct zbuf payload;
	struct zbuf extensions;
	struct nhrp_packet_header *hdr;
	enum nhrp_route_type route_type;
	struct prefix route_prefix;
	union sockunion src_nbma, src_proto, dst_proto;
};

struct nhrp_reqid_pool {
	struct hash *reqid_hash;
	uint32_t next_request_id;
};

struct nhrp_reqid {
	uint32_t request_id;
	void (*cb)(struct nhrp_reqid *, void *);
};

extern struct list *nhrp_vrf_list;
DECLARE_QOBJ_TYPE(nhrp_vrf);

enum nhrp_cache_type {
	NHRP_CACHE_INVALID = 0,
	NHRP_CACHE_INCOMPLETE,
	NHRP_CACHE_NEGATIVE,
	NHRP_CACHE_CACHED,
	NHRP_CACHE_DYNAMIC,
	NHRP_CACHE_NHS,
	NHRP_CACHE_STATIC,
	NHRP_CACHE_LOCAL,
	NHRP_CACHE_NUM_TYPES
};

extern struct nhrp_vrf *nhrp_get_context(const char *name);
extern struct nhrp_vrf *find_nhrp_vrf(const char *vrfname);
extern struct nhrp_vrf *find_nhrp_vrf_id(vrf_id_t vrf_id);
extern int nhrp_config_write_vrf(struct vty *vty,
				 struct nhrp_vrf *nhrp_vrf);

extern const char *const nhrp_cache_type_str[];
extern unsigned long nhrp_cache_counts[NHRP_CACHE_NUM_TYPES];

struct nhrp_cache_config {
	struct interface *ifp;
	union sockunion remote_addr;
	enum nhrp_cache_type type;
	union sockunion nbma;
};

struct nhrp_cache {
	struct interface *ifp;
	union sockunion remote_addr;

	unsigned map : 1;
	unsigned used : 1;
	unsigned route_installed : 1;
	unsigned nhrp_route_installed : 1;

	struct notifier_block peer_notifier;
	struct notifier_block newpeer_notifier;
	struct notifier_list notifier_list;
	struct nhrp_reqid eventid;
	struct thread *t_timeout;
	struct thread *t_auth;

	struct {
		enum nhrp_cache_type type;
		union sockunion remote_nbma_natoa;
		union sockunion remote_nbma_claimed;
		struct nhrp_peer *peer;
		time_t expires;
		uint32_t mtu;
		int holding_time;
	} cur, new;
};

struct nhrp_shortcut {
	struct prefix *p;
	union sockunion addr;

	struct nhrp_reqid reqid;
	struct thread *t_timer;

	enum nhrp_cache_type type;
	unsigned int holding_time;
	unsigned route_installed : 1;
	unsigned expiring : 1;

	struct nhrp_cache *cache;
	struct notifier_block cache_notifier;
	struct nhrp_vrf *nhrp_vrf;
};

struct nhrp_nhs {
	struct interface *ifp;
	struct list_head nhslist_entry;

	unsigned hub : 1;
	afi_t afi;
	union sockunion proto_addr;
	const char *nbma_fqdn; /* IP-address or FQDN */

	struct thread *t_resolve;
	struct resolver_query dns_resolve;
	struct list_head reglist_head;
};

struct nhrp_multicast {
	struct interface *ifp;
	struct list_head list_entry;
	afi_t afi;
	union sockunion nbma_addr; /* IP-address */
};

struct nhrp_registration {
	struct list_head reglist_entry;
	struct thread *t_register;
	struct nhrp_nhs *nhs;
	struct nhrp_reqid reqid;
	unsigned int timeout;
	unsigned mark : 1;
	union sockunion proto_addr;
	struct nhrp_peer *peer;
	struct notifier_block peer_notifier;
};

#define NHRP_IFF_SHORTCUT		0x0001
#define NHRP_IFF_REDIRECT		0x0002
#define NHRP_IFF_REG_NO_UNIQUE		0x0100

struct nhrp_interface {
	struct interface *ifp;

	unsigned enabled : 1;

	char *ipsec_profile, *ipsec_fallback_profile;
	char *source, *vrfname;

	union sockunion nbma;
	union sockunion nat_nbma;
	unsigned int link_idx;
	unsigned int link_vrf_id;
	uint32_t i_grekey;
	uint32_t o_grekey;

	struct hash *peer_hash;
	struct hash *cache_config_hash;
	struct hash *cache_hash;

	struct notifier_list notifier_list;

	struct interface *nbmaifp;
	struct notifier_block nbmanifp_notifier;

	struct nhrp_afi_data {
		unsigned flags;
		unsigned short configured : 1;
		union sockunion addr;
		uint32_t network_id;
		short configured_mtu;
		unsigned short mtu;
		unsigned int holdtime;
		struct list_head nhslist_head;
		struct list_head mcastlist_head;
	} afi[AFI_MAX];
};

struct nhrp_gre_info {
	ifindex_t ifindex;
	struct in_addr vtep_ip; /* IFLA_GRE_LOCAL */
	struct in_addr vtep_ip_remote; /* IFLA_GRE_REMOTE */
	uint32_t ikey;
	uint32_t okey;
	ifindex_t ifindex_link; /* Interface index of interface
				 * linked with GRE
				 */
	vrf_id_t vrfid_link;
};

extern struct zebra_privs_t nhrpd_privs;

int sock_open_unix(const char *path, vrf_id_t vrf_id);

void nhrp_interface_init(void);
void nhrp_interface_init_vrf(struct nhrp_vrf *nhrp_vrf);
void nhrp_interface_update(struct interface *ifp);
void nhrp_interface_update_mtu(struct interface *ifp, afi_t afi);
void nhrp_interface_update_nbma(struct interface *ifp,
				struct nhrp_gre_info *gre_info);

int nhrp_interface_add(ZAPI_CALLBACK_ARGS);
int nhrp_interface_delete(ZAPI_CALLBACK_ARGS);
int nhrp_interface_up(ZAPI_CALLBACK_ARGS);
int nhrp_interface_down(ZAPI_CALLBACK_ARGS);
int nhrp_interface_address_add(ZAPI_CALLBACK_ARGS);
int nhrp_interface_address_delete(ZAPI_CALLBACK_ARGS);
void nhrp_neighbor_operation(ZAPI_CALLBACK_ARGS);
void nhrp_gre_update(ZAPI_CALLBACK_ARGS);

void nhrp_interface_notify_add(struct interface *ifp, struct notifier_block *n,
			       notifier_fn_t fn);
void nhrp_interface_notify_del(struct interface *ifp, struct notifier_block *n);
void nhrp_interface_set_protection(struct interface *ifp, const char *profile,
				   const char *fallback_profile);
void nhrp_interface_set_source(struct interface *ifp, const char *ifname,
			       const char *vrfname);
extern int nhrp_ifp_create(struct interface *ifp);
extern int nhrp_ifp_up(struct interface *ifp);
extern int nhrp_ifp_down(struct interface *ifp);
extern int nhrp_ifp_destroy(struct interface *ifp);

int nhrp_interface_is_ptop(struct nhrp_vrf *nhrp_vrf, int ifindex,
			   uint8_t *addr, size_t *addrlen);

int nhrp_nhs_add(struct interface *ifp, afi_t afi, union sockunion *proto_addr,
		 const char *nbma_fqdn);
int nhrp_nhs_del(struct interface *ifp, afi_t afi, union sockunion *proto_addr,
		 const char *nbma_fqdn);
int nhrp_nhs_free(struct nhrp_nhs *nhs);
void nhrp_nhs_terminate(struct nhrp_vrf *nhrp_vrf);
void nhrp_nhs_init(struct nhrp_vrf *nhrp_vrf);
void nhrp_nhs_foreach(struct interface *ifp, afi_t afi,
		      void (*cb)(struct nhrp_nhs *, struct nhrp_registration *,
				 void *),
		      void *ctx);
void nhrp_nhs_interface_del(struct interface *ifp);

int nhrp_multicast_add(struct interface *ifp, afi_t afi,
		       union sockunion *nbma_addr);
int nhrp_multicast_del(struct interface *ifp, afi_t afi,
		       union sockunion *nbma_addr);
void nhrp_multicast_interface_del(struct interface *ifp);
void nhrp_multicast_foreach(struct interface *ifp, afi_t afi,
			    void (*cb)(struct nhrp_multicast *, void *),
			    void *ctx);
void netlink_mcast_set_nflog_group(struct nhrp_vrf *nhrp_vrf, int nlgroup);

void nhrp_route_update_nhrp(const struct prefix *p, struct interface *ifp,
			    struct nhrp_vrf *nhrp_vrf);
void nhrp_route_announce(int add, enum nhrp_cache_type type,
			 const struct prefix *p, struct interface *ifp,
			 const union sockunion *nexthop, uint32_t mtu);
int nhrp_route_read(ZAPI_CALLBACK_ARGS);
int nhrp_route_get_nexthop(const union sockunion *addr, struct prefix *p,
			   union sockunion *via, struct interface **ifp,
			   struct nhrp_vrf *nhrp_vrf);
enum nhrp_route_type nhrp_route_address(struct interface *in_ifp,
					union sockunion *addr, struct prefix *p,
					struct nhrp_peer **peer,
					struct nhrp_vrf *nhrp_vrf);

extern int interface_config_write_vrf(struct vty *vty,
				      struct nhrp_vrf *nhrp_vrf);
extern void nhrp_instance_register(struct nhrp_vrf *nhrp_vrf, bool on);
void nhrp_config_init(void);

void nhrp_shortcut_init(struct nhrp_vrf *nhrp_vrf);
void nhrp_shortcut_terminate(struct nhrp_vrf *nhrp_vrf);
void nhrp_shortcut_initiate(union sockunion *addr, struct nhrp_vrf *nhrp_vrf);
void nhrp_shortcut_foreach(afi_t afi,
			   void (*cb)(struct nhrp_shortcut *, void *),
			   void *ctx,
			   struct nhrp_vrf *nhrp_vrf);
void nhrp_shortcut_purge(struct nhrp_shortcut *s, int force);
void nhrp_shortcut_prefix_change(const struct prefix *p, int deleted,
				 struct nhrp_vrf *nhrp_vrf);

void nhrp_cache_interface_del(struct interface *ifp);
void nhrp_cache_config_free(struct nhrp_cache_config *c);
struct nhrp_cache_config *nhrp_cache_config_get(struct interface *ifp,
						union sockunion *remote_addr,
						int create);
struct nhrp_cache *nhrp_cache_get(struct interface *ifp,
				  union sockunion *remote_addr, int create);
void nhrp_cache_foreach(struct interface *ifp,
			void (*cb)(struct nhrp_cache *, void *), void *ctx);
void nhrp_cache_config_foreach(struct interface *ifp,
			       void (*cb)(struct nhrp_cache_config *, void *), void *ctx);
void nhrp_cache_set_used(struct nhrp_cache *, int);
int nhrp_cache_update_binding(struct nhrp_cache *, enum nhrp_cache_type type,
			      int holding_time, struct nhrp_peer *p,
			      uint32_t mtu, union sockunion *nbma_natoa,
			      union sockunion *claimed_nbma);
void nhrp_cache_notify_add(struct nhrp_cache *c, struct notifier_block *,
			   notifier_fn_t);
void nhrp_cache_notify_del(struct nhrp_cache *c, struct notifier_block *);

void nhrp_vc_init(struct nhrp_vrf *nhrp_vrf);
void nhrp_vc_terminate(struct nhrp_vrf *nhrp_vrf);
struct nhrp_vc *nhrp_vc_get(const union sockunion *src,
			    const union sockunion *dst, int create,
			    struct nhrp_vrf *nhrp_vrf);
int nhrp_vc_ipsec_updown(uint32_t child_id, struct nhrp_vrf *nhrp_vrf, struct nhrp_vc *vc);
void nhrp_vc_notify_add(struct nhrp_vc *, struct notifier_block *,
			notifier_fn_t);
void nhrp_vc_notify_del(struct nhrp_vc *, struct notifier_block *);
void nhrp_vc_foreach(void (*cb)(struct nhrp_vc *, void *),
		     void *ctx, struct nhrp_vrf *nhrp_vrf);
unsigned long nhrp_vc_count(struct nhrp_vrf *nhrp_vrf);
void nhrp_vc_reset(struct nhrp_vrf *nhrp_vrf);

void vici_init(struct nhrp_vrf *nhrp_vrf);
void vici_terminate(struct nhrp_vrf *nhrp_vrf, bool complete);
void vici_terminate_vc_by_profile_name(struct nhrp_vrf *nhrp_vrf, char *profile_name);
void vici_terminate_vc_by_ike_id(struct nhrp_vrf *nhrp_vrf, unsigned int ike_id);
void vici_register(struct interface *ifp, vrf_id_t link_vrf_id);
void vici_unregister(struct interface *ifp, vrf_id_t link_vrf_id);
void vici_terminate(struct nhrp_vrf *nhrp_vrf, bool complete);
void vici_request_vc(const char *profile, union sockunion *src,
		     union sockunion *dst, int prio,
		     struct nhrp_vrf *nhrp_vrf,
		     struct nhrp_interface *nifp);

void evmgr_init(struct nhrp_vrf *nhrp_vrf);
void evmgr_terminate(struct nhrp_vrf *nhrp_vrf);
void evmgr_set_socket(struct nhrp_vrf *nhrp_vrf, const char *socket);
void evmgr_notify(const char *name, struct nhrp_cache *c,
		  void (*cb)(struct nhrp_reqid *, void *));

struct nhrp_packet_header *nhrp_packet_push(struct zbuf *zb, uint8_t type,
					    const union sockunion *src_nbma,
					    const union sockunion *src_proto,
					    const union sockunion *dst_proto);
void nhrp_packet_complete(struct zbuf *zb, struct nhrp_packet_header *hdr);
uint16_t nhrp_packet_calculate_checksum(const uint8_t *pdu, uint16_t len);

struct nhrp_packet_header *nhrp_packet_pull(struct zbuf *zb,
					    union sockunion *src_nbma,
					    union sockunion *src_proto,
					    union sockunion *dst_proto);

struct nhrp_cie_header *nhrp_cie_push(struct zbuf *zb, uint8_t code,
				      const union sockunion *nbma,
				      const union sockunion *proto);
struct nhrp_cie_header *nhrp_cie_pull(struct zbuf *zb,
				      struct nhrp_packet_header *hdr,
				      union sockunion *nbma,
				      union sockunion *proto);

struct nhrp_extension_header *
nhrp_ext_push(struct zbuf *zb, struct nhrp_packet_header *hdr, uint16_t type);
void nhrp_ext_complete(struct zbuf *zb, struct nhrp_extension_header *ext);
struct nhrp_extension_header *nhrp_ext_pull(struct zbuf *zb,
					    struct zbuf *payload);
void nhrp_ext_request(struct zbuf *zb, struct nhrp_packet_header *hdr,
		      struct interface *);
int nhrp_ext_reply(struct zbuf *zb, struct nhrp_packet_header *hdr,
		   struct interface *ifp, struct nhrp_extension_header *ext,
		   struct zbuf *extpayload);

uint32_t nhrp_reqid_alloc(struct nhrp_reqid_pool *, struct nhrp_reqid *r,
			  void (*cb)(struct nhrp_reqid *, void *));
void nhrp_reqid_free(struct nhrp_reqid_pool *, struct nhrp_reqid *r);
struct nhrp_reqid *nhrp_reqid_lookup(struct nhrp_reqid_pool *, uint32_t reqid);

int nhrp_packet_init(struct nhrp_vrf *nhrp_vrf);

void nhrp_peer_interface_del(struct interface *ifp);
struct nhrp_peer *nhrp_peer_get(struct interface *ifp,
				const union sockunion *remote_nbma);
struct nhrp_peer *nhrp_peer_ref(struct nhrp_peer *p);
void nhrp_peer_unref(struct nhrp_peer *p);
int nhrp_peer_check(struct nhrp_peer *p, int establish);
void nhrp_peer_notify_add(struct nhrp_peer *p, struct notifier_block *,
			  notifier_fn_t);
void nhrp_peer_notify_del(struct nhrp_peer *p, struct notifier_block *);
void nhrp_peer_recv(struct nhrp_peer *p, struct zbuf *zb);
void nhrp_peer_send(struct nhrp_peer *p, struct zbuf *zb);
void nhrp_peer_send_indication(struct interface *ifp, uint16_t p_type,
			       char *buf, uint32_t len);

int nhrp_nhs_match_ip(union sockunion *in_ip, struct nhrp_interface *nifp);

#endif
