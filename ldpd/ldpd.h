/*$OpenBSD$*//**Copyright(c)2013,2016RenatoWestphal<renato@openbsd.org>*Copyrigh
t(c)2009MicheleMarchetto<michele@openbsd.org>*Copyright(c)2004EsbenNorby<norby@o
penbsd.org>*Copyright(c)2003,2004HenningBrauer<henning@openbsd.org>**Permissiont
ouse,copy,modify,anddistributethissoftwareforany*purposewithorwithoutfeeishereby
granted,providedthattheabove*copyrightnoticeandthispermissionnoticeappearinallco
pies.**THESOFTWAREISPROVIDED"ASIS"ANDTHEAUTHORDISCLAIMSALLWARRANTIES*WITHREGARDT
OTHISSOFTWAREINCLUDINGALLIMPLIEDWARRANTIESOF*MERCHANTABILITYANDFITNESS.INNOEVENT
SHALLTHEAUTHORBELIABLEFOR*ANYSPECIAL,DIRECT,INDIRECT,ORCONSEQUENTIALDAMAGESORANY
DAMAGES*WHATSOEVERRESULTINGFROMLOSSOFUSE,DATAORPROFITS,WHETHERINAN*ACTIONOFCONTR
ACT,NEGLIGENCEOROTHERTORTIOUSACTION,ARISINGOUTOF*ORINCONNECTIONWITHTHEUSEORPERFO
RMANCEOFTHISSOFTWARE.*/#ifndef_LDPD_H_#define_LDPD_H_#include"queue.h"#include"o
penbsd-tree.h"#include"imsg.h"#include"thread.h"#include"qobj.h"#include"prefix.
h"#include"filter.h"#include"vty.h"#include"pw.h"#include"zclient.h"#include"ldp
.h"#defineCONF_FILE"/etc/ldpd.conf"#defineLDPD_USER"_ldpd"#defineLDPD_FD_ASYNC3#
defineLDPD_FD_SYNC4#defineLDPD_OPT_VERBOSE0x00000001#defineLDPD_OPT_VERBOSE20x00
000002#defineLDPD_OPT_NOACTION0x00000004#defineTCP_MD5_KEY_LEN80#defineRT_BUF_SI
ZE16384#defineMAX_RTSOCK_BUF128*1024#defineLDP_BACKLOG128#defineF_LDPD_INSERTED0
x0001#defineF_CONNECTED0x0002#defineF_STATIC0x0004#defineF_DYNAMIC0x0008#defineF
_REJECT0x0010#defineF_BLACKHOLE0x0020#defineF_REDISTRIBUTED0x0040structevbuf{str
uctmsgbufwbuf;structthread*ev;int(*handler)(structthread*);void*arg;};structimsg
ev{structimsgbufibuf;int(*handler_write)(structthread*);structthread*ev_write;in
t(*handler_read)(structthread*);structthread*ev_read;};enumimsg_type{IMSG_NONE,I
MSG_CTL_RELOAD,IMSG_CTL_SHOW_INTERFACE,IMSG_CTL_SHOW_DISCOVERY,IMSG_CTL_SHOW_DIS
COVERY_DTL,IMSG_CTL_SHOW_DISC_IFACE,IMSG_CTL_SHOW_DISC_TNBR,IMSG_CTL_SHOW_DISC_A
DJ,IMSG_CTL_SHOW_NBR,IMSG_CTL_SHOW_NBR_DISC,IMSG_CTL_SHOW_NBR_END,IMSG_CTL_SHOW_
LIB,IMSG_CTL_SHOW_LIB_BEGIN,IMSG_CTL_SHOW_LIB_SENT,IMSG_CTL_SHOW_LIB_RCVD,IMSG_C
TL_SHOW_LIB_END,IMSG_CTL_SHOW_L2VPN_PW,IMSG_CTL_SHOW_L2VPN_BINDING,IMSG_CTL_CLEA
R_NBR,IMSG_CTL_FIB_COUPLE,IMSG_CTL_FIB_DECOUPLE,IMSG_CTL_KROUTE,IMSG_CTL_KROUTE_
ADDR,IMSG_CTL_IFINFO,IMSG_CTL_END,IMSG_CTL_LOG_VERBOSE,IMSG_KLABEL_CHANGE,IMSG_K
LABEL_DELETE,IMSG_KPW_ADD,IMSG_KPW_DELETE,IMSG_KPW_SET,IMSG_KPW_UNSET,IMSG_IFSTA
TUS,IMSG_NEWADDR,IMSG_DELADDR,IMSG_RTRID_UPDATE,IMSG_LABEL_MAPPING,IMSG_LABEL_MA
PPING_FULL,IMSG_LABEL_REQUEST,IMSG_LABEL_RELEASE,IMSG_LABEL_WITHDRAW,IMSG_LABEL_
ABORT,IMSG_REQUEST_ADD,IMSG_REQUEST_ADD_END,IMSG_MAPPING_ADD,IMSG_MAPPING_ADD_EN
D,IMSG_RELEASE_ADD,IMSG_RELEASE_ADD_END,IMSG_WITHDRAW_ADD,IMSG_WITHDRAW_ADD_END,
IMSG_ADDRESS_ADD,IMSG_ADDRESS_DEL,IMSG_NOTIFICATION,IMSG_NOTIFICATION_SEND,IMSG_
NEIGHBOR_UP,IMSG_NEIGHBOR_DOWN,IMSG_NETWORK_ADD,IMSG_NETWORK_UPDATE,IMSG_SOCKET_
IPC,IMSG_SOCKET_NET,IMSG_CLOSE_SOCKETS,IMSG_REQUEST_SOCKETS,IMSG_SETUP_SOCKETS,I
MSG_RECONF_CONF,IMSG_RECONF_IFACE,IMSG_RECONF_TNBR,IMSG_RECONF_NBRP,IMSG_RECONF_
L2VPN,IMSG_RECONF_L2VPN_IF,IMSG_RECONF_L2VPN_PW,IMSG_RECONF_L2VPN_IPW,IMSG_RECON
F_END,IMSG_DEBUG_UPDATE,IMSG_LOG,IMSG_ACL_CHECK,IMSG_INIT,IMSG_PW_UPDATE};struct
ldpd_init{charuser[256];chargroup[256];charctl_sock_path[MAXPATHLEN];charzclient
_serv_path[MAXPATHLEN];unsignedshortinstance;};unionldpd_addr{structin_addrv4;st
ructin6_addrv6;};#defineIN6_IS_SCOPE_EMBED(a)\((IN6_IS_ADDR_LINKLOCAL(a))||\(IN6
_IS_ADDR_MC_LINKLOCAL(a))||\(IN6_IS_ADDR_MC_INTFACELOCAL(a)))/*interfacestates*/
#defineIF_STA_DOWN0x01#defineIF_STA_ACTIVE0x02/*targetedneighborstates*/#defineT
NBR_STA_DOWN0x01#defineTNBR_STA_ACTIVE0x02/*interfacetypes*/enumiface_type{IF_TY
PE_POINTOPOINT,IF_TYPE_BROADCAST};/*neighborstates*/#defineNBR_STA_PRESENT0x0001
#defineNBR_STA_INITIAL0x0002#defineNBR_STA_OPENREC0x0004#defineNBR_STA_OPENSENT0
x0008#defineNBR_STA_OPER0x0010#defineNBR_STA_SESSION(NBR_STA_INITIAL|NBR_STA_OPE
NREC|\NBR_STA_OPENSENT|NBR_STA_OPER)/*neighborevents*/enumnbr_event{NBR_EVT_NOTH
ING,NBR_EVT_MATCH_ADJ,NBR_EVT_CONNECT_UP,NBR_EVT_CLOSE_SESSION,NBR_EVT_INIT_RCVD
,NBR_EVT_KEEPALIVE_RCVD,NBR_EVT_PDU_RCVD,NBR_EVT_PDU_SENT,NBR_EVT_INIT_SENT};/*n
eighboractions*/enumnbr_action{NBR_ACT_NOTHING,NBR_ACT_RST_KTIMEOUT,NBR_ACT_SESS
ION_EST,NBR_ACT_RST_KTIMER,NBR_ACT_CONNECT_SETUP,NBR_ACT_PASSIVE_INIT,NBR_ACT_KE
EPALIVE_SEND,NBR_ACT_CLOSE_SESSION};/*forwarddeclarations*/RB_HEAD(global_adj_he
ad,adj);RB_HEAD(nbr_adj_head,adj);RB_HEAD(ia_adj_head,adj);structmap{uint8_ttype
;uint32_tmsg_id;union{struct{uint16_taf;unionldpd_addrprefix;uint8_tprefixlen;}p
refix;struct{uint16_ttype;uint32_tpwid;uint32_tgroup_id;uint16_tifmtu;}pwid;stru
ct{uint8_ttype;union{uint16_tprefix_af;uint16_tpw_type;}u;}twcard;}fec;struct{ui
nt32_tstatus_code;uint32_tmsg_id;uint16_tmsg_type;}st;uint32_tlabel;uint32_trequ
estid;uint32_tpw_status;uint8_tflags;};#defineF_MAP_REQ_ID0x01/*optionalrequestm
essageidpresent*/#defineF_MAP_STATUS0x02/*status*/#defineF_MAP_PW_CWORD0x04/*pse
udowirecontrolword*/#defineF_MAP_PW_ID0x08/*pseudowireconnectionid*/#defineF_MAP
_PW_IFMTU0x10/*pseudowireinterfaceparameter*/#defineF_MAP_PW_STATUS0x20/*pseudow
irestatus*/structnotify_msg{uint32_tstatus_code;uint32_tmsg_id;/*networkbyteorde
r*/uint16_tmsg_type;/*networkbyteorder*/uint32_tpw_status;structmapfec;struct{ui
nt16_ttype;uint16_tlength;char*data;}rtlvs;uint8_tflags;};#defineF_NOTIF_PW_STAT
US0x01/*pseudowirestatustlvpresent*/#defineF_NOTIF_FEC0x02/*fectlvpresent*/#defi
neF_NOTIF_RETURNED_TLVS0x04/*returnedtlvspresent*/structif_addr{LIST_ENTRY(if_ad
dr)entry;intaf;unionldpd_addraddr;uint8_tprefixlen;unionldpd_addrdstbrd;};LIST_H
EAD(if_addr_head,if_addr);structiface_af{structiface*iface;intaf;intenabled;ints
tate;structia_adj_headadj_tree;time_tuptime;structthread*hello_timer;uint16_thel
lo_holdtime;uint16_thello_interval;};structiface{RB_ENTRY(iface)entry;charname[I
F_NAMESIZE];unsignedintifindex;structif_addr_headaddr_list;structin6_addrlinkloc
al;enumiface_typetype;intoperative;structiface_afipv4;structiface_afipv6;QOBJ_FI
ELDS};RB_HEAD(iface_head,iface);RB_PROTOTYPE(iface_head,iface,entry,iface_compar
e);DECLARE_QOBJ_TYPE(iface)/*sourceoftargetedhellos*/structtnbr{RB_ENTRY(tnbr)en
try;structthread*hello_timer;structadj*adj;intaf;unionldpd_addraddr;intstate;uin
t16_tpw_count;uint8_tflags;QOBJ_FIELDS};RB_HEAD(tnbr_head,tnbr);RB_PROTOTYPE(tnb
r_head,tnbr,entry,tnbr_compare);DECLARE_QOBJ_TYPE(tnbr)#defineF_TNBR_CONFIGURED0
x01#defineF_TNBR_DYNAMIC0x02enumauth_method{AUTH_NONE,AUTH_MD5SIG};/*neighborspe
cificparameters*/structnbr_params{RB_ENTRY(nbr_params)entry;structin_addrlsr_id;
uint16_tkeepalive;intgtsm_enabled;uint8_tgtsm_hops;struct{enumauth_methodmethod;
charmd5key[TCP_MD5_KEY_LEN];uint8_tmd5key_len;}auth;uint8_tflags;QOBJ_FIELDS};RB
_HEAD(nbrp_head,nbr_params);RB_PROTOTYPE(nbrp_head,nbr_params,entry,nbr_params_c
ompare);DECLARE_QOBJ_TYPE(nbr_params)#defineF_NBRP_KEEPALIVE0x01#defineF_NBRP_GT
SM0x02#defineF_NBRP_GTSM_HOPS0x04structldp_stats{uint32_tkalive_sent;uint32_tkal
ive_rcvd;uint32_taddr_sent;uint32_taddr_rcvd;uint32_taddrwdraw_sent;uint32_taddr
wdraw_rcvd;uint32_tnotif_sent;uint32_tnotif_rcvd;uint32_tcapability_sent;uint32_
tcapability_rcvd;uint32_tlabelmap_sent;uint32_tlabelmap_rcvd;uint32_tlabelreq_se
nt;uint32_tlabelreq_rcvd;uint32_tlabelwdraw_sent;uint32_tlabelwdraw_rcvd;uint32_
tlabelrel_sent;uint32_tlabelrel_rcvd;uint32_tlabelabreq_sent;uint32_tlabelabreq_
rcvd;};structl2vpn_if{RB_ENTRY(l2vpn_if)entry;structl2vpn*l2vpn;charifname[IF_NA
MESIZE];unsignedintifindex;intoperative;uint8_tmac[ETH_ALEN];QOBJ_FIELDS};RB_HEA
D(l2vpn_if_head,l2vpn_if);RB_PROTOTYPE(l2vpn_if_head,l2vpn_if,entry,l2vpn_if_com
pare);DECLARE_QOBJ_TYPE(l2vpn_if)structl2vpn_pw{RB_ENTRY(l2vpn_pw)entry;structl2
vpn*l2vpn;structin_addrlsr_id;intaf;unionldpd_addraddr;uint32_tpwid;charifname[I
F_NAMESIZE];unsignedintifindex;boolenabled;uint32_tremote_group;uint16_tremote_m
tu;uint32_tlocal_status;uint32_tremote_status;uint8_tflags;QOBJ_FIELDS};RB_HEAD(
l2vpn_pw_head,l2vpn_pw);RB_PROTOTYPE(l2vpn_pw_head,l2vpn_pw,entry,l2vpn_pw_compa
re);DECLARE_QOBJ_TYPE(l2vpn_pw)#defineF_PW_STATUSTLV_CONF0x01/*statustlvconfigur
ed*/#defineF_PW_STATUSTLV0x02/*statustlvnegotiated*/#defineF_PW_CWORD_CONF0x04/*
controlwordconfigured*/#defineF_PW_CWORD0x08/*controlwordnegotiated*/#defineF_PW
_STATIC_NBR_ADDR0x10/*staticneighboraddressconfigured*/structl2vpn{RB_ENTRY(l2vp
n)entry;charname[L2VPN_NAME_LEN];inttype;intpw_type;intmtu;charbr_ifname[IF_NAME
SIZE];unsignedintbr_ifindex;structl2vpn_if_headif_tree;structl2vpn_pw_headpw_tre
e;structl2vpn_pw_headpw_inactive_tree;QOBJ_FIELDS};RB_HEAD(l2vpn_head,l2vpn);RB_
PROTOTYPE(l2vpn_head,l2vpn,entry,l2vpn_compare);DECLARE_QOBJ_TYPE(l2vpn)#defineL
2VPN_TYPE_VPWS1#defineL2VPN_TYPE_VPLS2/*ldp_conf*/enumldpd_process{PROC_MAIN,PRO
C_LDP_ENGINE,PROC_LDE_ENGINE}ldpd_process;staticconstchar*constlog_procnames[]={
"parent","ldpe","lde"};enumsocket_type{LDP_SOCKET_DISC,LDP_SOCKET_EDISC,LDP_SOCK
ET_SESSION};enumhello_type{HELLO_LINK,HELLO_TARGETED};structldpd_af_conf{uint16_
tkeepalive;uint16_tlhello_holdtime;uint16_tlhello_interval;uint16_tthello_holdti
me;uint16_tthello_interval;unionldpd_addrtrans_addr;characl_thello_accept_from[A
CL_NAMSIZ];characl_label_allocate_for[ACL_NAMSIZ];characl_label_advertise_to[ACL
_NAMSIZ];characl_label_advertise_for[ACL_NAMSIZ];characl_label_expnull_for[ACL_N
AMSIZ];characl_label_accept_from[ACL_NAMSIZ];characl_label_accept_for[ACL_NAMSIZ
];intflags;};#defineF_LDPD_AF_ENABLED0x0001#defineF_LDPD_AF_THELLO_ACCEPT0x0002#
defineF_LDPD_AF_EXPNULL0x0004#defineF_LDPD_AF_NO_GTSM0x0008#defineF_LDPD_AF_ALLO
CHOSTONLY0x0010structldpd_conf{structin_addrrtr_id;structldpd_af_confipv4;struct
ldpd_af_confipv6;structiface_headiface_tree;structtnbr_headtnbr_tree;structnbrp_
headnbrp_tree;structl2vpn_headl2vpn_tree;uint16_tlhello_holdtime;uint16_tlhello_
interval;uint16_tthello_holdtime;uint16_tthello_interval;uint16_ttrans_pref;intf
lags;QOBJ_FIELDS};DECLARE_QOBJ_TYPE(ldpd_conf)#defineF_LDPD_NO_FIB_UPDATE0x0001#
defineF_LDPD_DS_CISCO_INTEROP0x0002#defineF_LDPD_ENABLED0x0004structldpd_af_glob
al{structthread*disc_ev;structthread*edisc_ev;intldp_disc_socket;intldp_edisc_so
cket;intldp_session_socket;};structldpd_global{intcmd_opts;structin_addrrtr_id;s
tructldpd_af_globalipv4;structldpd_af_globalipv6;uint32_tconf_seqnum;intpfkeysoc
k;structif_addr_headaddr_list;structglobal_adj_headadj_tree;structin_addrmcast_a
ddr_v4;structin6_addrmcast_addr_v6;TAILQ_HEAD(,pending_conn)pending_conns;};/*kr
oute*/structkroute{intaf;unionldpd_addrprefix;uint8_tprefixlen;unionldpd_addrnex
thop;uint32_tlocal_label;uint32_tremote_label;unsignedshortifindex;uint8_tpriori
ty;uint16_tflags;};structkaddr{charifname[IF_NAMESIZE];unsignedshortifindex;inta
f;unionldpd_addraddr;uint8_tprefixlen;unionldpd_addrdstbrd;};structkif{charifnam
e[IF_NAMESIZE];unsignedshortifindex;intflags;intoperative;uint8_tmac[ETH_ALEN];i
ntmtu;};structacl_check{characl[ACL_NAMSIZ];intaf;unionldpd_addraddr;uint8_tpref
ixlen;};/*controldatastructures*/structctl_iface{intaf;charname[IF_NAMESIZE];uns
ignedintifindex;intstate;enumiface_typetype;uint16_thello_holdtime;uint16_thello
_interval;time_tuptime;uint16_tadj_cnt;};structctl_disc_if{charname[IF_NAMESIZE]
;intactive_v4;intactive_v6;intno_adj;};structctl_disc_tnbr{intaf;unionldpd_addra
ddr;intno_adj;};structctl_adj{intaf;structin_addrid;enumhello_typetype;charifnam
e[IF_NAMESIZE];unionldpd_addrsrc_addr;uint16_tholdtime;uint16_tholdtime_remainin
g;unionldpd_addrtrans_addr;intds_tlv;};structctl_nbr{intaf;structin_addrid;union
ldpd_addrladdr;in_port_tlport;unionldpd_addrraddr;in_port_trport;enumauth_method
auth_method;uint16_tholdtime;time_tuptime;intnbr_state;structldp_statsstats;intf
lags;};structctl_rt{intaf;unionldpd_addrprefix;uint8_tprefixlen;structin_addrnex
thop;/*lsr-id*/uint32_tlocal_label;uint32_tremote_label;uint8_tflags;uint8_tin_u
se;intno_downstream;};structctl_pw{uint16_ttype;charl2vpn_name[L2VPN_NAME_LEN];c
harifname[IF_NAMESIZE];uint32_tpwid;structin_addrlsr_id;uint32_tlocal_label;uint
32_tlocal_gid;uint16_tlocal_ifmtu;uint8_tlocal_cword;uint32_tremote_label;uint32
_tremote_gid;uint16_tremote_ifmtu;uint8_tremote_cword;uint32_tstatus;};externstr
uctldpd_conf*ldpd_conf,*vty_conf;externstructldpd_globalglobal;externstructldpd_
initinit;/*parse.y*/structldpd_conf*parse_config(char*);intcmdline_symset(char*)
;/*kroute.c*/voidpw2zpw(structl2vpn_pw*,structzapi_pw*);voidkif_redistribute(con
stchar*);intkr_change(structkroute*);intkr_delete(structkroute*);intkmpw_add(str
uctzapi_pw*);intkmpw_del(structzapi_pw*);intkmpw_set(structzapi_pw*);intkmpw_uns
et(structzapi_pw*);/*util.c*/uint8_tmask2prefixlen(in_addr_t);uint8_tmask2prefix
len6(structsockaddr_in6*);in_addr_tprefixlen2mask(uint8_t);structin6_addr*prefix
len2mask6(uint8_t);voidldp_applymask(int,unionldpd_addr*,constunionldpd_addr*,in
t);intldp_addrcmp(int,constunionldpd_addr*,constunionldpd_addr*);intldp_addrisse
t(int,constunionldpd_addr*);intldp_prefixcmp(int,constunionldpd_addr*,constunion
ldpd_addr*,uint8_t);intbad_addr_v4(structin_addr);intbad_addr_v6(structin6_addr*
);intbad_addr(int,unionldpd_addr*);voidembedscope(structsockaddr_in6*);voidrecov
erscope(structsockaddr_in6*);voidaddscope(structsockaddr_in6*,uint32_t);voidclea
rscope(structin6_addr*);structsockaddr*addr2sa(intaf,unionldpd_addr*,uint16_t);v
oidsa2addr(structsockaddr*,int*,unionldpd_addr*,in_port_t*);socklen_tsockaddr_le
n(structsockaddr*);/*ldpd.c*/intldp_write_handler(structthread*);voidmain_imsg_c
ompose_ldpe(int,pid_t,void*,uint16_t);voidmain_imsg_compose_lde(int,pid_t,void*,
uint16_t);intmain_imsg_compose_both(enumimsg_type,void*,uint16_t);voidimsg_event
_add(structimsgev*);intimsg_compose_event(structimsgev*,uint16_t,uint32_t,pid_t,
int,void*,uint16_t);voidevbuf_enqueue(structevbuf*,structibuf*);voidevbuf_event_
add(structevbuf*);voidevbuf_init(structevbuf*,int,int(*)(structthread*),void*);v
oidevbuf_clear(structevbuf*);intldp_acl_request(structimsgev*,char*,int,unionldp
d_addr*,uint8_t);voidldp_acl_reply(structimsgev*,structacl_check*);structldpd_af
_conf*ldp_af_conf_get(structldpd_conf*,int);structldpd_af_global*ldp_af_global_g
et(structldpd_global*,int);intldp_is_dual_stack(structldpd_conf*);in_addr_tldp_r
tr_id_get(structldpd_conf*);intldp_config_apply(structvty*,structldpd_conf*);voi
dldp_clear_config(structldpd_conf*);voidmerge_config(structldpd_conf*,structldpd
_conf*);structldpd_conf*config_new_empty(void);voidconfig_clear(structldpd_conf*
);/*ldp_vty_conf.c*//*NOTE:theparameters'namesshouldbepreservedbecauseofcodegen*
/structiface*iface_new_api(structldpd_conf*conf,constchar*name);voidiface_del_ap
i(structldpd_conf*conf,structiface*iface);structtnbr*tnbr_new_api(structldpd_con
f*conf,intaf,unionldpd_addr*addr);voidtnbr_del_api(structldpd_conf*conf,structtn
br*tnbr);structnbr_params*nbrp_new_api(structldpd_conf*conf,structin_addrlsr_id)
;voidnbrp_del_api(structldpd_conf*conf,structnbr_params*nbrp);structl2vpn*l2vpn_
new_api(structldpd_conf*conf,constchar*name);voidl2vpn_del_api(structldpd_conf*c
onf,structl2vpn*l2vpn);structl2vpn_if*l2vpn_if_new_api(structldpd_conf*conf,stru
ctl2vpn*l2vpn,constchar*ifname);voidl2vpn_if_del_api(structl2vpn*l2vpn,structl2v
pn_if*lif);structl2vpn_pw*l2vpn_pw_new_api(structldpd_conf*conf,structl2vpn*l2vp
n,constchar*ifname);voidl2vpn_pw_del_api(structl2vpn*l2vpn,structl2vpn_pw*pw);/*
socket.c*/intldp_create_socket(int,enumsocket_type);voidsock_set_nonblock(int);v
oidsock_set_cloexec(int);voidsock_set_recvbuf(int);intsock_set_reuse(int,int);in
tsock_set_bindany(int,int);intsock_set_md5sig(int,int,unionldpd_addr*,constchar*
);intsock_set_ipv4_tos(int,int);intsock_set_ipv4_pktinfo(int,int);intsock_set_ip
v4_recvdstaddr(int,int);intsock_set_ipv4_recvif(int,int);intsock_set_ipv4_minttl
(int,int);intsock_set_ipv4_ucast_ttl(intfd,int);intsock_set_ipv4_mcast_ttl(int,u
int8_t);intsock_set_ipv4_mcast(structiface*);intsock_set_ipv4_mcast_loop(int);in
tsock_set_ipv6_dscp(int,int);intsock_set_ipv6_pktinfo(int,int);intsock_set_ipv6_
minhopcount(int,int);intsock_set_ipv6_ucast_hops(int,int);intsock_set_ipv6_mcast
_hops(int,int);intsock_set_ipv6_mcast(structiface*);intsock_set_ipv6_mcast_loop(
int);/*logmsg.h*/structin6_addr;unionldpd_addr;structhello_source;structfec;cons
tchar*log_sockaddr(void*);constchar*log_in6addr(conststructin6_addr*);constchar*
log_in6addr_scope(conststructin6_addr*,unsignedint);constchar*log_addr(int,const
unionldpd_addr*);char*log_label(uint32_t);constchar*log_time(time_t);char*log_he
llo_src(conststructhello_source*);constchar*log_map(conststructmap*);constchar*l
og_fec(conststructfec*);constchar*af_name(int);constchar*socket_name(int);constc
har*nbr_state_name(int);constchar*if_state_name(int);constchar*if_type_name(enum
iface_type);constchar*msg_name(uint16_t);constchar*status_code_name(uint32_t);co
nstchar*pw_type_name(uint16_t);/*quagga*/externstructthread_master*master;extern
charctl_sock_path[MAXPATHLEN];/*ldp_zebra.c*/voidldp_zebra_init(structthread_mas
ter*);voidldp_zebra_destroy(void);/*compatibility*/#ifndef__OpenBSD__#define__IP
V6_ADDR_MC_SCOPE(a)((a)->s6_addr[1]&0x0f)#define__IPV6_ADDR_SCOPE_INTFACELOCAL0x
01#defineIN6_IS_ADDR_MC_INTFACELOCAL(a)\(IN6_IS_ADDR_MULTICAST(a)&&\(__IPV6_ADDR
_MC_SCOPE(a)==__IPV6_ADDR_SCOPE_INTFACELOCAL))#endif#endif/*_LDPD_H_*/