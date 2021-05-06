/*
 * VRF functions.
 * Copyright (C) 2014 6WIND S.A.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

/* for basename */
#include <libgen.h>

#include "if.h"
#include "vrf.h"
#include "vrf_int.h"
#include "prefix.h"
#include "table.h"
#include "log.h"
#include "memory.h"
#include "command.h"
#include "ns.h"
#include "privs.h"
#include "nexthop_group.h"
#include "lib_errors.h"
#include "northbound.h"
#include "northbound_cli.h"

/* default VRF name value used when VRF backend is not NETNS */
#define VRF_DEFAULT_NAME_INTERNAL "default"

DEFINE_MTYPE_STATIC(LIB, VRF, "VRF");
DEFINE_MTYPE_STATIC(LIB, VRF_BITMAP, "VRF bit-map");

DEFINE_QOBJ_TYPE(vrf);

static __inline int vrf_id_compare(const struct vrf *, const struct vrf *);
static __inline int vrf_name_compare(const struct vrf *, const struct vrf *);

RB_GENERATE(vrf_id_head, vrf, id_entry, vrf_id_compare);
RB_GENERATE(vrf_name_head, vrf, name_entry, vrf_name_compare);

struct vrf_id_head vrfs_by_id = RB_INITIALIZER(&vrfs_by_id);
struct vrf_name_head vrfs_by_name = RB_INITIALIZER(&vrfs_by_name);

static int vrf_backend;
static int vrf_backend_configured;
static struct zebra_privs_t *vrf_daemon_privs;
static char vrf_default_name[VRF_NAMSIZ] = VRF_DEFAULT_NAME_INTERNAL;

/*
 * Turn on/off debug code
 * for vrf.
 */
static int debug_vrf = 0;

/* Holding VRF hooks  */
static struct vrf_master {
	int (*vrf_new_hook)(struct vrf *);
	int (*vrf_delete_hook)(struct vrf *);
	int (*vrf_enable_hook)(struct vrf *);
	int (*vrf_disable_hook)(struct vrf *);
	int (*vrf_update_name_hook)(struct vrf *vrf);
} vrf_master = {
	0,
};

static int vrf_is_enabled(struct vrf *vrf);

/* VRF list existance check by name. */
struct vrf *vrf_lookup_by_name(const char *name)
{
	struct vrf vrf;
	strlcpy(vrf.name, name, sizeof(vrf.name));
	return (RB_FIND(vrf_name_head, &vrfs_by_name, &vrf));
}

static __inline int vrf_id_compare(const struct vrf *a, const struct vrf *b)
{
	return (a->vrf_id - b->vrf_id);
}

static int vrf_name_compare(const struct vrf *a, const struct vrf *b)
{
	return strcmp(a->name, b->name);
}

/* if ns_id is different and not VRF_UNKNOWN,
 * then update vrf identifier, and enable VRF
 */
static void vrf_update_vrf_id(ns_id_t ns_id, void *opaqueptr)
{
	ns_id_t vrf_id = (vrf_id_t)ns_id;
	vrf_id_t old_vrf_id;
	struct vrf *vrf = (struct vrf *)opaqueptr;

	if (!vrf)
		return;
	old_vrf_id = vrf->vrf_id;
	if (vrf_id == vrf->vrf_id)
		return;
	if (vrf->vrf_id != VRF_UNKNOWN)
		RB_REMOVE(vrf_id_head, &vrfs_by_id, vrf);
	vrf->vrf_id = vrf_id;
	RB_INSERT(vrf_id_head, &vrfs_by_id, vrf);
	if (old_vrf_id == VRF_UNKNOWN)
		vrf_enable(vrf);
}

int vrf_switch_to_netns(vrf_id_t vrf_id)
{
	char *name;
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

	/* VRF is default VRF. silently ignore */
	if (!vrf || vrf->vrf_id == VRF_DEFAULT)
		return 1;	/* 1 = default */
	/* VRF has no NETNS backend. silently ignore */
	if (vrf->data.l.netns_name[0] == '\0')
		return 2;	/* 2 = no netns */
	name = ns_netns_pathname(NULL, vrf->data.l.netns_name);
	if (debug_vrf)
		zlog_debug("VRF_SWITCH: %s(%u)", name, vrf->vrf_id);
	return ns_switch_to_netns(name);
}

int vrf_switchback_to_initial(void)
{
	int ret = ns_switchback_to_initial();

	if (ret == 0 && debug_vrf)
		zlog_debug("VRF_SWITCHBACK");
	return ret;
}

/* Get a VRF. If not found, create one.
 * Arg:
 *   name   - The name of the vrf.  May be NULL if unknown.
 *   vrf_id - The vrf_id of the vrf.  May be VRF_UNKNOWN if unknown
 * Description: Please note that this routine can be called with just the name
 * and 0 vrf-id
 */
struct vrf *vrf_get(vrf_id_t vrf_id, const char *name)
{
	struct vrf *vrf = NULL;
	int new = 0;

	/* Nothing to see, move along here */
	if (!name && vrf_id == VRF_UNKNOWN)
		return NULL;

	/* attempt to find already available VRF
	 */
	if (name)
		vrf = vrf_lookup_by_name(name);
	if (vrf && vrf_id != VRF_UNKNOWN
	    && vrf->vrf_id != VRF_UNKNOWN
	    && vrf->vrf_id != vrf_id) {
		zlog_debug("VRF_GET: avoid %s creation(%u), same name exists (%u)",
			   name, vrf_id, vrf->vrf_id);
		return NULL;
	}
	/* Try to find VRF both by ID and name */
	if (!vrf && vrf_id != VRF_UNKNOWN)
		vrf = vrf_lookup_by_id(vrf_id);

	if (vrf == NULL) {
		vrf = XCALLOC(MTYPE_VRF, sizeof(struct vrf));
		vrf->vrf_id = VRF_UNKNOWN;
		QOBJ_REG(vrf, vrf);
		new = 1;

		if (debug_vrf)
			zlog_debug("VRF(%u) %s is created.", vrf_id,
				   (name) ? name : "(NULL)");
	}

	/* Set identifier */
	if (vrf_id != VRF_UNKNOWN && vrf->vrf_id == VRF_UNKNOWN) {
		vrf->vrf_id = vrf_id;
		RB_INSERT(vrf_id_head, &vrfs_by_id, vrf);
	}

	/* Set name */
	if (name && vrf->name[0] != '\0' && strcmp(name, vrf->name)) {
		/* update the vrf name */
		RB_REMOVE(vrf_name_head, &vrfs_by_name, vrf);
		strlcpy(vrf->data.l.netns_name,
			name, NS_NAMSIZ);
		strlcpy(vrf->name, name, sizeof(vrf->name));
		RB_INSERT(vrf_name_head, &vrfs_by_name, vrf);
		if (vrf->vrf_id == VRF_DEFAULT)
			vrf_set_default_name(vrf->name, false);
	} else if (name && vrf->name[0] == '\0') {
		strlcpy(vrf->name, name, sizeof(vrf->name));
		RB_INSERT(vrf_name_head, &vrfs_by_name, vrf);
	}
	if (new &&vrf_master.vrf_new_hook)
		(*vrf_master.vrf_new_hook)(vrf);

	return vrf;
}

/* Update a VRF. If not found, create one.
 * Arg:
 *   name   - The name of the vrf.
 *   vrf_id - The vrf_id of the vrf.
 * Description: This function first finds the vrf using its name. If the vrf is
 * found and the vrf-id of the existing vrf does not match the new vrf id, it
 * will disable the existing vrf and update it with new vrf-id. If the vrf is
 * not found, it will create the vrf with given name and the new vrf id.
 */
struct vrf *vrf_update(vrf_id_t new_vrf_id, const char *name)
{
	struct vrf *vrf = NULL;

	/*Treat VRF add for existing vrf as update
	 * Update VRF ID and also update in VRF ID table
	 */
	if (name)
		vrf = vrf_lookup_by_name(name);
	if (vrf && new_vrf_id != VRF_UNKNOWN && vrf->vrf_id != VRF_UNKNOWN
	    && vrf->vrf_id != new_vrf_id) {
		if (debug_vrf) {
			zlog_debug(
				"Vrf Update event: %s old id: %u, new id: %u",
				name, vrf->vrf_id, new_vrf_id);
		}

		/*Disable the vrf to simulate implicit delete
		 * so that all stale routes are deleted
		 * This vrf will be enabled down the line
		 */
		vrf_disable(vrf);


		RB_REMOVE(vrf_id_head, &vrfs_by_id, vrf);
		vrf->vrf_id = new_vrf_id;
		RB_INSERT(vrf_id_head, &vrfs_by_id, vrf);

	} else {

		/*
		 * vrf_get is implied creation if it does not exist
		 */
		vrf = vrf_get(new_vrf_id, name);
	}
	return vrf;
}

/* Delete a VRF. This is called when the underlying VRF goes away, a
 * pre-configured VRF is deleted or when shutting down (vrf_terminate()).
 */
void vrf_delete(struct vrf *vrf)
{
	if (debug_vrf)
		zlog_debug("VRF %s(%u) is to be deleted.", vrf->name,
			   vrf->vrf_id);

	if (vrf_is_enabled(vrf))
		vrf_disable(vrf);

	/* If the VRF is user configured, it'll stick around, just remove
	 * the ID mapping. Interfaces assigned to this VRF should've been
	 * removed already as part of the VRF going down.
	 */
	if (vrf_is_user_cfged(vrf)) {
		if (vrf->vrf_id != VRF_UNKNOWN) {
			/* Delete any VRF interfaces - should be only
			 * the VRF itself, other interfaces should've
			 * been moved out of the VRF.
			 */
			if_terminate(vrf);
			RB_REMOVE(vrf_id_head, &vrfs_by_id, vrf);
			vrf->vrf_id = VRF_UNKNOWN;
		}
		return;
	}

	if (vrf_master.vrf_delete_hook)
		(*vrf_master.vrf_delete_hook)(vrf);

	QOBJ_UNREG(vrf);
	if_terminate(vrf);

	if (vrf->vrf_id != VRF_UNKNOWN)
		RB_REMOVE(vrf_id_head, &vrfs_by_id, vrf);
	if (vrf->name[0] != '\0')
		RB_REMOVE(vrf_name_head, &vrfs_by_name, vrf);

	XFREE(MTYPE_VRF, vrf);
}

/* Look up a VRF by identifier. */
struct vrf *vrf_lookup_by_id(vrf_id_t vrf_id)
{
	struct vrf vrf;
	vrf.vrf_id = vrf_id;
	return (RB_FIND(vrf_id_head, &vrfs_by_id, &vrf));
}

/*
 * Enable a VRF - that is, let the VRF be ready to use.
 * The VRF_ENABLE_HOOK callback will be called to inform
 * that they can allocate resources in this VRF.
 *
 * RETURN: 1 - enabled successfully; otherwise, 0.
 */
int vrf_enable(struct vrf *vrf)
{
	if (vrf_is_enabled(vrf))
		return 1;

	if (debug_vrf)
		zlog_debug("VRF %s(%u) is enabled.", vrf->name, vrf->vrf_id);

	SET_FLAG(vrf->status, VRF_ACTIVE);

	if (vrf_master.vrf_enable_hook)
		(*vrf_master.vrf_enable_hook)(vrf);

	/*
	 * If we have any nexthop group entries that
	 * are awaiting vrf initialization then
	 * let's let people know about it
	 */
	nexthop_group_enable_vrf(vrf);

	return 1;
}

/*
 * Disable a VRF - that is, let the VRF be unusable.
 * The VRF_DELETE_HOOK callback will be called to inform
 * that they must release the resources in the VRF.
 */
void vrf_disable(struct vrf *vrf)
{
	if (!vrf_is_enabled(vrf))
		return;

	UNSET_FLAG(vrf->status, VRF_ACTIVE);

	if (debug_vrf)
		zlog_debug("VRF %s(%u) is to be disabled.", vrf->name,
			   vrf->vrf_id);

	/* Till now, nothing to be done for the default VRF. */
	// Pending: see why this statement.


	/*
	 * When the vrf is disabled let's
	 * handle all nexthop-groups associated
	 * with this vrf
	 */
	nexthop_group_disable_vrf(vrf);

	if (vrf_master.vrf_disable_hook)
		(*vrf_master.vrf_disable_hook)(vrf);
}

const char *vrf_id_to_name(vrf_id_t vrf_id)
{
	struct vrf *vrf;

	if (vrf_id == VRF_DEFAULT)
		return VRF_DEFAULT_NAME;

	vrf = vrf_lookup_by_id(vrf_id);
	return VRF_LOGNAME(vrf);
}

vrf_id_t vrf_name_to_id(const char *name)
{
	struct vrf *vrf;
	vrf_id_t vrf_id = VRF_DEFAULT; // Pending: need a way to return invalid
				       // id/ routine not used.

	if (!name)
		return vrf_id;
	vrf = vrf_lookup_by_name(name);
	if (vrf)
		vrf_id = vrf->vrf_id;

	return vrf_id;
}

/* Get the data pointer of the specified VRF. If not found, create one. */
void *vrf_info_get(vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_get(vrf_id, NULL);
	return vrf->info;
}

/* Look up the data pointer of the specified VRF. */
void *vrf_info_lookup(vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	return vrf ? vrf->info : NULL;
}

/*
 * VRF hash for storing set or not.
 */
struct vrf_bit_set {
	vrf_id_t vrf_id;
	bool set;
};

static unsigned int vrf_hash_bitmap_key(const void *data)
{
	const struct vrf_bit_set *bit = data;

	return bit->vrf_id;
}

static bool vrf_hash_bitmap_cmp(const void *a, const void *b)
{
	const struct vrf_bit_set *bit1 = a;
	const struct vrf_bit_set *bit2 = b;

	return bit1->vrf_id == bit2->vrf_id;
}

static void *vrf_hash_bitmap_alloc(void *data)
{
	struct vrf_bit_set *copy = data;
	struct vrf_bit_set *bit;

	bit = XMALLOC(MTYPE_VRF_BITMAP, sizeof(*bit));
	bit->vrf_id = copy->vrf_id;

	return bit;
}

static void vrf_hash_bitmap_free(void *data)
{
	struct vrf_bit_set *bit = data;

	XFREE(MTYPE_VRF_BITMAP, bit);
}

vrf_bitmap_t vrf_bitmap_init(void)
{
	return hash_create_size(32, vrf_hash_bitmap_key, vrf_hash_bitmap_cmp,
				"VRF BIT HASH");
}

void vrf_bitmap_free(vrf_bitmap_t bmap)
{
	struct hash *vrf_hash = bmap;

	if (vrf_hash == NULL)
		return;

	hash_clean(vrf_hash, vrf_hash_bitmap_free);
	hash_free(vrf_hash);
}

void vrf_bitmap_set(vrf_bitmap_t bmap, vrf_id_t vrf_id)
{
	struct vrf_bit_set lookup = { .vrf_id = vrf_id };
	struct hash *vrf_hash = bmap;
	struct vrf_bit_set *bit;

	if (vrf_hash == NULL || vrf_id == VRF_UNKNOWN)
		return;

	bit = hash_get(vrf_hash, &lookup, vrf_hash_bitmap_alloc);
	bit->set = true;
}

void vrf_bitmap_unset(vrf_bitmap_t bmap, vrf_id_t vrf_id)
{
	struct vrf_bit_set lookup = { .vrf_id = vrf_id };
	struct hash *vrf_hash = bmap;
	struct vrf_bit_set *bit;

	if (vrf_hash == NULL || vrf_id == VRF_UNKNOWN)
		return;

	bit = hash_get(vrf_hash, &lookup, vrf_hash_bitmap_alloc);
	bit->set = false;
}

int vrf_bitmap_check(vrf_bitmap_t bmap, vrf_id_t vrf_id)
{
	struct vrf_bit_set lookup = { .vrf_id = vrf_id };
	struct hash *vrf_hash = bmap;
	struct vrf_bit_set *bit;

	if (vrf_hash == NULL || vrf_id == VRF_UNKNOWN)
		return 0;

	bit = hash_lookup(vrf_hash, &lookup);
	if (bit)
		return bit->set;

	return 0;
}

static void vrf_autocomplete(vector comps, struct cmd_token *token)
{
	struct vrf *vrf = NULL;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, vrf->name));
}

static const struct cmd_variable_handler vrf_var_handlers[] = {
	{
		.varname = "vrf",
		.completions = vrf_autocomplete,
	},
	{
		.varname = "vrf_name",
		.completions = vrf_autocomplete,
	},
	{
		.varname = "nexthop_vrf",
		.completions = vrf_autocomplete,
	},
	{.completions = NULL},
};

/* Initialize VRF module. */
void vrf_init(int (*create)(struct vrf *), int (*enable)(struct vrf *),
	      int (*disable)(struct vrf *), int (*destroy)(struct vrf *),
	      int ((*update)(struct vrf *)))
{
	struct vrf *default_vrf;

	/* initialise NS, in case VRF backend if NETNS */
	ns_init();
	if (debug_vrf)
		zlog_debug("%s: Initializing VRF subsystem", __func__);

	vrf_master.vrf_new_hook = create;
	vrf_master.vrf_enable_hook = enable;
	vrf_master.vrf_disable_hook = disable;
	vrf_master.vrf_delete_hook = destroy;
	vrf_master.vrf_update_name_hook = update;

	/* The default VRF always exists. */
	default_vrf = vrf_get(VRF_DEFAULT, VRF_DEFAULT_NAME);
	if (!default_vrf) {
		flog_err(EC_LIB_VRF_START,
			 "vrf_init: failed to create the default VRF!");
		exit(1);
	}
	if (vrf_is_backend_netns()) {
		struct ns *ns;

		strlcpy(default_vrf->data.l.netns_name,
			VRF_DEFAULT_NAME, NS_NAMSIZ);
		ns = ns_lookup(NS_DEFAULT);
		ns->vrf_ctxt = default_vrf;
		default_vrf->ns_ctxt = ns;
	}

	/* Enable the default VRF. */
	if (!vrf_enable(default_vrf)) {
		flog_err(EC_LIB_VRF_START,
			 "vrf_init: failed to enable the default VRF!");
		exit(1);
	}

	cmd_variable_handler_register(vrf_var_handlers);
}

/* Terminate VRF module. */
void vrf_terminate(void)
{
	struct vrf *vrf;

	if (debug_vrf)
		zlog_debug("%s: Shutting down vrf subsystem", __func__);

	while (!RB_EMPTY(vrf_id_head, &vrfs_by_id)) {
		vrf = RB_ROOT(vrf_id_head, &vrfs_by_id);

		/* Clear configured flag and invoke delete. */
		UNSET_FLAG(vrf->status, VRF_CONFIGURED);
		vrf_delete(vrf);
	}

	while (!RB_EMPTY(vrf_name_head, &vrfs_by_name)) {
		vrf = RB_ROOT(vrf_name_head, &vrfs_by_name);

		/* Clear configured flag and invoke delete. */
		UNSET_FLAG(vrf->status, VRF_CONFIGURED);
		vrf_delete(vrf);
	}
}

int vrf_socket(int domain, int type, int protocol, vrf_id_t vrf_id,
	       const char *interfacename)
{
	int ret, save_errno, ret2;

	ret = vrf_switch_to_netns(vrf_id);
	if (ret < 0)
		flog_err_sys(EC_LIB_SOCKET, "%s: Can't switch to VRF %u (%s)",
			     __func__, vrf_id, safe_strerror(errno));

	ret = socket(domain, type, protocol);
	save_errno = errno;
	ret2 = vrf_switchback_to_initial();
	if (ret2 < 0)
		flog_err_sys(EC_LIB_SOCKET,
			     "%s: Can't switchback from VRF %u (%s)", __func__,
			     vrf_id, safe_strerror(errno));
	errno = save_errno;
	if (ret <= 0)
		return ret;
	ret2 = vrf_bind(vrf_id, ret, interfacename);
	if (ret2 < 0) {
		close(ret);
		ret = ret2;
	}
	return ret;
}

int vrf_is_backend_netns(void)
{
	return (vrf_backend == VRF_BACKEND_NETNS);
}

int vrf_get_backend(void)
{
	if (!vrf_backend_configured)
		return VRF_BACKEND_UNKNOWN;
	return vrf_backend;
}

int vrf_configure_backend(enum vrf_backend_type backend)
{
	/* Work around issue in old gcc */
	switch (backend) {
	case VRF_BACKEND_UNKNOWN:
	case VRF_BACKEND_NETNS:
	case VRF_BACKEND_VRF_LITE:
		break;
	default:
		return -1;
	}

	vrf_backend = backend;
	vrf_backend_configured = 1;

	return 0;
}

int vrf_handler_create(struct vty *vty, const char *vrfname,
		       struct vrf **vrf)
{
	struct vrf *vrfp;
	char xpath_list[XPATH_MAXLEN];
	int ret;

	if (strlen(vrfname) > VRF_NAMSIZ) {
		if (vty)
			vty_out(vty,
				"%% VRF name %s invalid: length exceeds %d bytes\n",
				vrfname, VRF_NAMSIZ);
		else
			flog_warn(
				EC_LIB_VRF_LENGTH,
				"%% VRF name %s invalid: length exceeds %d bytes",
				vrfname, VRF_NAMSIZ);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (vty) {
		snprintf(xpath_list, sizeof(xpath_list), FRR_VRF_KEY_XPATH,
			 vrfname);

		nb_cli_enqueue_change(vty, xpath_list, NB_OP_CREATE, NULL);
		ret = nb_cli_apply_changes_clear_pending(vty, xpath_list);
		if (ret == CMD_SUCCESS) {
			VTY_PUSH_XPATH(VRF_NODE, xpath_list);
			vrfp = vrf_lookup_by_name(vrfname);
			if (vrfp)
				VTY_PUSH_CONTEXT(VRF_NODE, vrfp);
		}
	} else {
		vrfp = vrf_get(VRF_UNKNOWN, vrfname);

		if (vrf)
			*vrf = vrfp;
	}
	return CMD_SUCCESS;
}

int vrf_netns_handler_create(struct vty *vty, struct vrf *vrf, char *pathname,
			     ns_id_t ns_id, ns_id_t internal_ns_id,
			     ns_id_t rel_def_ns_id)
{
	struct ns *ns = NULL;

	if (!vrf)
		return CMD_WARNING_CONFIG_FAILED;
	if (vrf->vrf_id != VRF_UNKNOWN && vrf->ns_ctxt == NULL) {
		if (vty)
			vty_out(vty,
				"VRF %u is already configured with VRF %s\n",
				vrf->vrf_id, vrf->name);
		else
			zlog_info("VRF %u is already configured with VRF %s",
				  vrf->vrf_id, vrf->name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (vrf->ns_ctxt != NULL) {
		ns = (struct ns *)vrf->ns_ctxt;
		if (!strcmp(ns->name, pathname)) {
			if (vty)
				vty_out(vty,
					"VRF %u already configured with NETNS %s\n",
					vrf->vrf_id, ns->name);
			else
				zlog_info(
					"VRF %u already configured with NETNS %s",
					vrf->vrf_id, ns->name);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	ns = ns_lookup_name(pathname);
	if (ns && ns->vrf_ctxt) {
		struct vrf *vrf2 = (struct vrf *)ns->vrf_ctxt;

		if (vrf2 == vrf)
			return CMD_SUCCESS;
		if (vty)
			vty_out(vty,
				"NS %s is already configured with VRF %u(%s)\n",
				ns->name, vrf2->vrf_id, vrf2->name);
		else
			zlog_info("NS %s is already configured with VRF %u(%s)",
				  ns->name, vrf2->vrf_id, vrf2->name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	ns = ns_get_created(ns, pathname, ns_id);
	ns->internal_ns_id = internal_ns_id;
	ns->relative_default_ns = rel_def_ns_id;
	ns->vrf_ctxt = (void *)vrf;
	vrf->ns_ctxt = (void *)ns;
	/* update VRF netns NAME */
	strlcpy(vrf->data.l.netns_name, basename(pathname), NS_NAMSIZ);

	if (!ns_enable(ns, vrf_update_vrf_id)) {
		if (vty)
			vty_out(vty, "Can not associate NS %u with NETNS %s\n",
				ns->ns_id, ns->name);
		else
			zlog_info("Can not associate NS %u with NETNS %s",
				  ns->ns_id, ns->name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

/* vrf CLI commands */
DEFUN_NOSH(vrf_exit,
           vrf_exit_cmd,
	   "exit-vrf",
	   "Exit current mode and down to previous mode\n")
{
	/* We have to set vrf context to default vrf */
	VTY_PUSH_CONTEXT(VRF_NODE, vrf_get(VRF_DEFAULT, VRF_DEFAULT_NAME));
	cmd_exit(vty);
	return CMD_SUCCESS;
}

DEFUN_YANG_NOSH (vrf,
       vrf_cmd,
       "vrf NAME",
       "Select a VRF to configure\n"
       "VRF's name\n")
{
	int idx_name = 1;
	const char *vrfname = argv[idx_name]->arg;

	return vrf_handler_create(vty, vrfname, NULL);
}

DEFUN_YANG (no_vrf,
       no_vrf_cmd,
       "no vrf NAME",
       NO_STR
       "Delete a pseudo VRF's configuration\n"
       "VRF's name\n")
{
	const char *vrfname = argv[2]->arg;
	char xpath_list[XPATH_MAXLEN];

	struct vrf *vrfp;

	vrfp = vrf_lookup_by_name(vrfname);

	if (vrfp == NULL)
		return CMD_SUCCESS;

	if (CHECK_FLAG(vrfp->status, VRF_ACTIVE)) {
		vty_out(vty, "%% Only inactive VRFs can be deleted\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath_list, sizeof(xpath_list), FRR_VRF_KEY_XPATH, vrfname);

	nb_cli_enqueue_change(vty, xpath_list, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, xpath_list);
}


static struct cmd_node vrf_node = {
	.name = "vrf",
	.node = VRF_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-vrf)# ",
};

DEFUN_NOSH (vrf_netns,
       vrf_netns_cmd,
       "netns NAME",
       "Attach VRF to a Namespace\n"
       "The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	int idx_name = 1, ret;
	char *pathname = ns_netns_pathname(vty, argv[idx_name]->arg);

	VTY_DECLVAR_CONTEXT(vrf, vrf);

	if (!pathname)
		return CMD_WARNING_CONFIG_FAILED;

	frr_with_privs(vrf_daemon_privs) {
		ret = vrf_netns_handler_create(vty, vrf, pathname,
					       NS_UNKNOWN,
					       NS_UNKNOWN,
					       NS_UNKNOWN);
	}
	return ret;
}

DEFUN_NOSH (no_vrf_netns,
	no_vrf_netns_cmd,
	"no netns [NAME]",
	NO_STR
	"Detach VRF from a Namespace\n"
	"The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	struct ns *ns = NULL;

	VTY_DECLVAR_CONTEXT(vrf, vrf);

	if (!vrf_is_backend_netns()) {
		vty_out(vty, "VRF backend is not Netns. Aborting\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!vrf->ns_ctxt) {
		vty_out(vty, "VRF %s(%u) is not configured with NetNS\n",
			vrf->name, vrf->vrf_id);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ns = (struct ns *)vrf->ns_ctxt;

	ns->vrf_ctxt = NULL;
	vrf_disable(vrf);
	/* vrf ID from VRF is necessary for Zebra
	 * so that propagate to other clients is done
	 */
	ns_delete(ns);
	vrf->ns_ctxt = NULL;
	return CMD_SUCCESS;
}

/*
 * Debug CLI for vrf's
 */
DEFUN (vrf_debug,
      vrf_debug_cmd,
      "debug vrf",
      DEBUG_STR
      "VRF Debugging\n")
{
	debug_vrf = 1;

	return CMD_SUCCESS;
}

DEFUN (no_vrf_debug,
      no_vrf_debug_cmd,
      "no debug vrf",
      NO_STR
      DEBUG_STR
      "VRF Debugging\n")
{
	debug_vrf = 0;

	return CMD_SUCCESS;
}

static int vrf_write_host(struct vty *vty)
{
	if (debug_vrf)
		vty_out(vty, "debug vrf\n");

	return 1;
}

static int vrf_write_host(struct vty *vty);
static struct cmd_node vrf_debug_node = {
	.name = "vrf debug",
	.node = VRF_DEBUG_NODE,
	.prompt = "",
	.config_write = vrf_write_host,
};

void vrf_install_commands(void)
{
	install_node(&vrf_debug_node);

	install_element(CONFIG_NODE, &vrf_debug_cmd);
	install_element(ENABLE_NODE, &vrf_debug_cmd);
	install_element(CONFIG_NODE, &no_vrf_debug_cmd);
	install_element(ENABLE_NODE, &no_vrf_debug_cmd);
}

void vrf_cmd_init(int (*writefunc)(struct vty *vty),
		  struct zebra_privs_t *daemon_privs)
{
	install_element(CONFIG_NODE, &vrf_cmd);
	install_element(CONFIG_NODE, &no_vrf_cmd);
	vrf_node.config_write = writefunc;
	install_node(&vrf_node);
	install_default(VRF_NODE);
	install_element(VRF_NODE, &vrf_exit_cmd);
	if (vrf_is_backend_netns() && ns_have_netns()) {
		/* Install NS commands. */
		vrf_daemon_privs = daemon_privs;
		install_element(VRF_NODE, &vrf_netns_cmd);
		install_element(VRF_NODE, &no_vrf_netns_cmd);
	}
}

void vrf_set_default_name(const char *default_name, bool force)
{
	struct vrf *def_vrf;
	static bool def_vrf_forced;

	def_vrf = vrf_lookup_by_id(VRF_DEFAULT);
	assert(default_name);
	if (def_vrf && !force && def_vrf_forced) {
		zlog_debug("VRF: %s, avoid changing name to %s, previously forced (%u)",
			   def_vrf->name, default_name,
			   def_vrf->vrf_id);
		return;
	}
	if (strmatch(vrf_default_name, default_name))
		return;
	snprintf(vrf_default_name, VRF_NAMSIZ, "%s", default_name);
	if (def_vrf) {
		if (force)
			def_vrf_forced = true;
		RB_REMOVE(vrf_name_head, &vrfs_by_name, def_vrf);
		strlcpy(def_vrf->data.l.netns_name,
			vrf_default_name, NS_NAMSIZ);
		strlcpy(def_vrf->name, vrf_default_name, sizeof(def_vrf->name));
		RB_INSERT(vrf_name_head, &vrfs_by_name, def_vrf);
		if (vrf_master.vrf_update_name_hook)
			(*vrf_master.vrf_update_name_hook)(def_vrf);
	}
}

const char *vrf_get_default_name(void)
{
	return vrf_default_name;
}

int vrf_bind(vrf_id_t vrf_id, int fd, const char *ifname)
{
	int ret = 0;
	struct interface *ifp;
	struct vrf *vrf;

	if (fd < 0)
		return -1;

	if (vrf_id == VRF_UNKNOWN)
		return -1;

	/* can't bind to a VRF that doesn't exist */
	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf_is_enabled(vrf))
		return -1;

	if (ifname && strcmp(ifname, vrf->name)) {
		/* binding to a regular interface */

		/* can't bind to an interface that doesn't exist */
		ifp = if_lookup_by_name(ifname, vrf_id);
		if (!ifp)
			return -1;
	} else {
		/* binding to a VRF device */

		/* nothing to do for netns */
		if (vrf_is_backend_netns())
			return 0;

		/* nothing to do for default vrf */
		if (vrf_id == VRF_DEFAULT)
			return 0;

		ifname = vrf->name;
	}

#ifdef SO_BINDTODEVICE
	ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
			 strlen(ifname) + 1);
	if (ret < 0)
		zlog_err("bind to interface %s failed, errno=%d", ifname,
			 errno);
#endif /* SO_BINDTODEVICE */
	return ret;
}
int vrf_getaddrinfo(const char *node, const char *service,
		    const struct addrinfo *hints, struct addrinfo **res,
		    vrf_id_t vrf_id)
{
	int ret, ret2, save_errno;

	ret = vrf_switch_to_netns(vrf_id);
	if (ret < 0)
		flog_err_sys(EC_LIB_SOCKET, "%s: Can't switch to VRF %u (%s)",
			     __func__, vrf_id, safe_strerror(errno));
	ret = getaddrinfo(node, service, hints, res);
	save_errno = errno;
	ret2 = vrf_switchback_to_initial();
	if (ret2 < 0)
		flog_err_sys(EC_LIB_SOCKET,
			     "%s: Can't switchback from VRF %u (%s)", __func__,
			     vrf_id, safe_strerror(errno));
	errno = save_errno;
	return ret;
}

int vrf_ioctl(vrf_id_t vrf_id, int d, unsigned long request, char *params)
{
	int ret, saved_errno, rc;

	ret = vrf_switch_to_netns(vrf_id);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s: Can't switch to VRF %u (%s)",
			     __func__, vrf_id, safe_strerror(errno));
		return 0;
	}
	rc = ioctl(d, request, params);
	saved_errno = errno;
	ret = vrf_switchback_to_initial();
	if (ret < 0)
		flog_err_sys(EC_LIB_SOCKET,
			     "%s: Can't switchback from VRF %u (%s)", __func__,
			     vrf_id, safe_strerror(errno));
	errno = saved_errno;
	return rc;
}

int vrf_sockunion_socket(const union sockunion *su, vrf_id_t vrf_id,
			 const char *interfacename)
{
	int ret, save_errno, ret2;

	ret = vrf_switch_to_netns(vrf_id);
	if (ret < 0)
		flog_err_sys(EC_LIB_SOCKET, "%s: Can't switch to VRF %u (%s)",
			     __func__, vrf_id, safe_strerror(errno));
	ret = sockunion_socket(su);
	save_errno = errno;
	ret2 = vrf_switchback_to_initial();
	if (ret2 < 0)
		flog_err_sys(EC_LIB_SOCKET,
			     "%s: Can't switchback from VRF %u (%s)", __func__,
			     vrf_id, safe_strerror(errno));
	errno = save_errno;

	if (ret <= 0)
		return ret;
	ret2 = vrf_bind(vrf_id, ret, interfacename);
	if (ret2 < 0) {
		close(ret);
		ret = ret2;
	}
	return ret;
}

vrf_id_t vrf_generate_id(void)
{
	static int vrf_id_local;

	return ++vrf_id_local;
}

/* ------- Northbound callbacks ------- */

/*
 * XPath: /frr-vrf:lib/vrf
 */
static int lib_vrf_create(struct nb_cb_create_args *args)
{
	const char *vrfname;
	struct vrf *vrfp;

	vrfname = yang_dnode_get_string(args->dnode, "./name");

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrfp = vrf_get(VRF_UNKNOWN, vrfname);

	SET_FLAG(vrfp->status, VRF_CONFIGURED);
	nb_running_set_entry(args->dnode, vrfp);

	return NB_OK;
}

static int lib_vrf_destroy(struct nb_cb_destroy_args *args)
{
	struct vrf *vrfp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		vrfp = nb_running_get_entry(args->dnode, NULL, true);
		if (CHECK_FLAG(vrfp->status, VRF_ACTIVE)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Only inactive VRFs can be deleted");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrfp = nb_running_unset_entry(args->dnode);

		/* Clear configured flag and invoke delete. */
		UNSET_FLAG(vrfp->status, VRF_CONFIGURED);
		vrf_delete(vrfp);
		break;
	}

	return NB_OK;
}

static const void *lib_vrf_get_next(struct nb_cb_get_next_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;

	if (args->list_entry == NULL) {
		vrfp = RB_MIN(vrf_name_head, &vrfs_by_name);
	} else {
		vrfp = RB_NEXT(vrf_name_head, vrfp);
	}

	return vrfp;
}

static int lib_vrf_get_keys(struct nb_cb_get_keys_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], vrfp->name, sizeof(args->keys->key[0]));

	return NB_OK;
}

static const void *lib_vrf_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *vrfname = args->keys->key[0];

	struct vrf *vrf = vrf_lookup_by_name(vrfname);

	return vrf;
}

/*
 * XPath: /frr-vrf:lib/vrf/id
 */
static struct yang_data *
lib_vrf_state_id_get_elem(struct nb_cb_get_elem_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;

	return yang_data_new_uint32(args->xpath, vrfp->vrf_id);
}

/*
 * XPath: /frr-vrf:lib/vrf/active
 */
static struct yang_data *
lib_vrf_state_active_get_elem(struct nb_cb_get_elem_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;

	if (vrfp->status == VRF_ACTIVE)
		return yang_data_new_bool(
			args->xpath, vrfp->status == VRF_ACTIVE ? true : false);

	return NULL;
}

/* clang-format off */
const struct frr_yang_module_info frr_vrf_info = {
	.name = "frr-vrf",
	.nodes = {
		{
			.xpath = "/frr-vrf:lib/vrf",
			.cbs = {
				.create = lib_vrf_create,
				.destroy = lib_vrf_destroy,
				.get_next = lib_vrf_get_next,
				.get_keys = lib_vrf_get_keys,
				.lookup_entry = lib_vrf_lookup_entry,
			},
			.priority = NB_DFLT_PRIORITY - 2,
		},
		{
			.xpath = "/frr-vrf:lib/vrf/state/id",
			.cbs = {
				.get_elem = lib_vrf_state_id_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/state/active",
			.cbs = {
				.get_elem = lib_vrf_state_active_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

