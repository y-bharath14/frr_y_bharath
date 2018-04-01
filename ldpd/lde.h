/*$OpenBSD$*//**Copyright(c)2013,2016RenatoWestphal<renato@openbsd.org>*Copyrigh
t(c)2009MicheleMarchetto<michele@openbsd.org>*Copyright(c)2004,2005EsbenNorby<no
rby@openbsd.org>**Permissiontouse,copy,modify,anddistributethissoftwareforany*pu
rposewithorwithoutfeeisherebygranted,providedthattheabove*copyrightnoticeandthis
permissionnoticeappearinallcopies.**THESOFTWAREISPROVIDED"ASIS"ANDTHEAUTHORDISCL
AIMSALLWARRANTIES*WITHREGARDTOTHISSOFTWAREINCLUDINGALLIMPLIEDWARRANTIESOF*MERCHA
NTABILITYANDFITNESS.INNOEVENTSHALLTHEAUTHORBELIABLEFOR*ANYSPECIAL,DIRECT,INDIREC
T,ORCONSEQUENTIALDAMAGESORANYDAMAGES*WHATSOEVERRESULTINGFROMLOSSOFUSE,DATAORPROF
ITS,WHETHERINAN*ACTIONOFCONTRACT,NEGLIGENCEOROTHERTORTIOUSACTION,ARISINGOUTOF*OR
INCONNECTIONWITHTHEUSEORPERFORMANCEOFTHISSOFTWARE.*/#ifndef_LDE_H_#define_LDE_H_
#include"queue.h"#include"openbsd-tree.h"#include"if.h"enumfec_type{FEC_TYPE_IPV
4,FEC_TYPE_IPV6,FEC_TYPE_PWID};structfec{RB_ENTRY(fec)entry;enumfec_typetype;uni
on{struct{structin_addrprefix;uint8_tprefixlen;}ipv4;struct{structin6_addrprefix
;uint8_tprefixlen;}ipv6;struct{uint16_ttype;uint32_tpwid;structin_addrlsr_id;}pw
id;}u;};RB_HEAD(fec_tree,fec);RB_PROTOTYPE(fec_tree,fec,entry,fec_compare)/*requ
estentries*/structlde_req{structfecfec;uint32_tmsg_id;};/*mappingentries*/struct
lde_map{structfecfec;structlde_map_head*head;/*fec_node'supstream/downstream*/RB
_ENTRY(lde_map)entry;structlde_nbr*nexthop;structmapmap;};RB_HEAD(lde_map_head,l
de_map);RB_PROTOTYPE(lde_map_head,lde_map,entry,lde_map_cmp);/*withdrawentries*/
structlde_wdraw{structfecfec;uint32_tlabel;};/*Addressesbelongingtoneighbor*/str
uctlde_addr{TAILQ_ENTRY(lde_addr)entry;intaf;unionldpd_addraddr;};/*justtheinfoL
DEneeds*/structlde_nbr{RB_ENTRY(lde_nbr)entry;uint32_tpeerid;structin_addrid;int
v4_enabled;/*announce/processv4msgs*/intv6_enabled;/*announce/processv6msgs*/int
flags;/*capabilities*/structfec_treerecv_req;structfec_treesent_req;structfec_tr
eerecv_map;structfec_treesent_map;structfec_treesent_map_pending;structfec_trees
ent_wdraw;TAILQ_HEAD(,lde_addr)addr_list;};RB_HEAD(nbr_tree,lde_nbr);RB_PROTOTYP
E(nbr_tree,lde_nbr,entry,lde_nbr_compare)structfec_nh{LIST_ENTRY(fec_nh)entry;in
taf;unionldpd_addrnexthop;ifindex_tifindex;uint32_tremote_label;uint8_tpriority;
uint8_tflags;};#defineF_FEC_NH_NEW0x01#defineF_FEC_NH_CONNECTED0x02structfec_nod
e{structfecfec;LIST_HEAD(,fec_nh)nexthops;/*fibnexthops*/structlde_map_headdowns
tream;/*recvmappings*/structlde_map_headupstream;/*sentmappings*/uint32_tlocal_l
abel;void*data;/*fecspecificdata*/};#defineCHUNK_SIZE64structlabel_chunk{uint32_
tstart;uint32_tend;uint64_tused_mask;};#defineLDE_GC_INTERVAL300externstructldpd
_conf*ldeconf;externstructfec_treeft;externstructnbr_treelde_nbrs;externstructth
read*gc_timer;/*lde.c*/voidlde(void);voidlde_init(structldpd_init*);intlde_imsg_
compose_parent(int,pid_t,void*,uint16_t);voidlde_imsg_compose_parent_sync(int,pi
d_t,void*,uint16_t);intlde_imsg_compose_ldpe(int,uint32_t,pid_t,void*,uint16_t);
intlde_acl_check(char*,int,unionldpd_addr*,uint8_t);uint32_tlde_update_label(str
uctfec_node*);voidlde_send_change_klabel(structfec_node*,structfec_nh*);voidlde_
send_delete_klabel(structfec_node*,structfec_nh*);voidlde_fec2map(structfec*,str
uctmap*);voidlde_map2fec(structmap*,structin_addr,structfec*);voidlde_send_label
mapping(structlde_nbr*,structfec_node*,int);voidlde_send_labelwithdraw(structlde
_nbr*,structfec_node*,structmap*,structstatus_tlv*);voidlde_send_labelwithdraw_w
card(structlde_nbr*,uint32_t);voidlde_send_labelwithdraw_twcard_prefix(structlde
_nbr*,uint16_t,uint32_t);voidlde_send_labelwithdraw_twcard_pwid(structlde_nbr*,u
int16_t,uint32_t);voidlde_send_labelwithdraw_pwid_wcard(structlde_nbr*,uint16_t,
uint32_t);voidlde_send_labelrelease(structlde_nbr*,structfec_node*,structmap*,ui
nt32_t);voidlde_send_notification(structlde_nbr*,uint32_t,uint32_t,uint16_t);voi
dlde_send_notification_eol_prefix(structlde_nbr*,int);voidlde_send_notification_
eol_pwid(structlde_nbr*,uint16_t);structlde_nbr*lde_nbr_find_by_lsrid(structin_a
ddr);structlde_nbr*lde_nbr_find_by_addr(int,unionldpd_addr*);structlde_map*lde_m
ap_add(structlde_nbr*,structfec_node*,int);voidlde_map_del(structlde_nbr*,struct
lde_map*,int);structfec*lde_map_pending_add(structlde_nbr*,structfec_node*);void
lde_map_pending_del(structlde_nbr*,structfec*);structlde_req*lde_req_add(structl
de_nbr*,structfec*,int);voidlde_req_del(structlde_nbr*,structlde_req*,int);struc
tlde_wdraw*lde_wdraw_add(structlde_nbr*,structfec_node*);voidlde_wdraw_del(struc
tlde_nbr*,structlde_wdraw*);voidlde_change_egress_label(int);structlde_addr*lde_
address_find(structlde_nbr*,int,unionldpd_addr*);/*lde_lib.c*/voidfec_init(struc
tfec_tree*);structfec*fec_find(structfec_tree*,structfec*);intfec_insert(structf
ec_tree*,structfec*);intfec_remove(structfec_tree*,structfec*);voidfec_clear(str
uctfec_tree*,void(*)(void*));voidrt_dump(pid_t);voidfec_snap(structlde_nbr*);voi
dfec_tree_clear(void);structfec_nh*fec_nh_find(structfec_node*,int,unionldpd_add
r*,ifindex_t,uint8_t);voidlde_kernel_insert(structfec*,int,unionldpd_addr*,ifind
ex_t,uint8_t,int,void*);voidlde_kernel_remove(structfec*,int,unionldpd_addr*,ifi
ndex_t,uint8_t);voidlde_kernel_update(structfec*);voidlde_check_mapping(structma
p*,structlde_nbr*);voidlde_check_request(structmap*,structlde_nbr*);voidlde_chec
k_request_wcard(structmap*,structlde_nbr*);voidlde_check_release(structmap*,stru
ctlde_nbr*);voidlde_check_release_wcard(structmap*,structlde_nbr*);voidlde_check
_withdraw(structmap*,structlde_nbr*);voidlde_check_withdraw_wcard(structmap*,str
uctlde_nbr*);intlde_wildcard_apply(structmap*,structfec*,structlde_map*);intlde_
gc_timer(structthread*);voidlde_gc_start_timer(void);voidlde_gc_stop_timer(void)
;/*l2vpn.c*/structl2vpn*l2vpn_new(constchar*);structl2vpn*l2vpn_find(structldpd_
conf*,constchar*);voidl2vpn_del(structl2vpn*);voidl2vpn_init(structl2vpn*);voidl
2vpn_exit(structl2vpn*);structl2vpn_if*l2vpn_if_new(structl2vpn*,constchar*);str
uctl2vpn_if*l2vpn_if_find(structl2vpn*,constchar*);voidl2vpn_if_update_info(stru
ctl2vpn_if*,structkif*);voidl2vpn_if_update(structl2vpn_if*);structl2vpn_pw*l2vp
n_pw_new(structl2vpn*,constchar*);structl2vpn_pw*l2vpn_pw_find(structl2vpn*,cons
tchar*);structl2vpn_pw*l2vpn_pw_find_active(structl2vpn*,constchar*);structl2vpn
_pw*l2vpn_pw_find_inactive(structl2vpn*,constchar*);voidl2vpn_pw_update_info(str
uctl2vpn_pw*,structkif*);voidl2vpn_pw_init(structl2vpn_pw*);voidl2vpn_pw_exit(st
ructl2vpn_pw*);voidl2vpn_pw_reset(structl2vpn_pw*);intl2vpn_pw_ok(structl2vpn_pw
*,structfec_nh*);intl2vpn_pw_negotiate(structlde_nbr*,structfec_node*,structmap*
);voidl2vpn_send_pw_status(structlde_nbr*,uint32_t,structfec*);voidl2vpn_send_pw
_status_wcard(structlde_nbr*,uint32_t,uint16_t,uint32_t);voidl2vpn_recv_pw_statu
s(structlde_nbr*,structnotify_msg*);voidl2vpn_recv_pw_status_wcard(structlde_nbr
*,structnotify_msg*);intl2vpn_pw_status_update(structzapi_pw_status*);voidl2vpn_
pw_ctl(pid_t);voidl2vpn_binding_ctl(pid_t);#endif/*_LDE_H_*/