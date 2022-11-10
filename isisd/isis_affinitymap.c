/* isisd affinitymap.
 * Copyright (C) 2022 6WIND
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
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
#include "lib/if.h"
#include "lib/vrf.h"
#include "isisd/isisd.h"
#include "isisd/isis_affinitymap.h"

#ifndef FABRICD

static bool isis_affinity_map_check_use(const char *affmap_name)
{
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);
	struct isis_area *area;
	struct listnode *area_node, *fa_node;
	struct flex_algo *fa;
	struct affinity_map *map;
	uint16_t pos;

	map = affinity_map_get(affmap_name);
	pos = map->bit_position;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, area_node, area)) {
		for (ALL_LIST_ELEMENTS_RO(area->flex_algos->flex_algos, fa_node,
					  fa)) {
			if (admin_group_get(&fa->admin_group_exclude_any,
					    pos) ||
			    admin_group_get(&fa->admin_group_include_any,
					    pos) ||
			    admin_group_get(&fa->admin_group_include_all, pos))
				return true;
		}
	}
	return false;
}

static void isis_affinity_map_update(const char *affmap_name, uint16_t old_pos,
				     uint16_t new_pos)
{
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);
	struct listnode *area_node, *fa_node;
	struct isis_area *area;
	struct flex_algo *fa;
	bool changed;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, area_node, area)) {
		changed = false;
		for (ALL_LIST_ELEMENTS_RO(area->flex_algos->flex_algos, fa_node,
					  fa)) {
			if (admin_group_get(&fa->admin_group_exclude_any,
					    old_pos)) {
				admin_group_unset(&fa->admin_group_exclude_any,
						  old_pos);
				admin_group_set(&fa->admin_group_exclude_any,
						new_pos);
				changed = true;
			}
			if (admin_group_get(&fa->admin_group_include_any,
					    old_pos)) {
				admin_group_unset(&fa->admin_group_include_any,
						  old_pos);
				admin_group_set(&fa->admin_group_include_any,
						new_pos);
				changed = true;
			}
			if (admin_group_get(&fa->admin_group_include_all,
					    old_pos)) {
				admin_group_unset(&fa->admin_group_include_all,
						  old_pos);
				admin_group_set(&fa->admin_group_include_all,
						new_pos);
				changed = true;
			}
		}
		if (changed)
			lsp_regenerate_schedule(area, area->is_type, 0);
	}
}

void isis_affinity_map_init(void)
{
	affinity_map_init();

	affinity_map_set_check_use_hook(isis_affinity_map_check_use);
	affinity_map_set_update_hook(isis_affinity_map_update);
}

#endif /* ifndef FABRICD */
