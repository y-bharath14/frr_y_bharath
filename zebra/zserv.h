/*Zebradaemonserverheader.*Copyright(C)1997,98KunihiroIshiguro**Thisfileispartof
GNUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/ormodifyit*undertheter
msoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eithervers
ion2,or(atyouroption)any*laterversion.**GNUZebraisdistributedinthehopethatitwill
beuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYo
rFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**You
shouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethef
ileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,
Boston,MA02110-1301USA*/#ifndef_ZEBRA_ZSERV_H#define_ZEBRA_ZSERV_H#include"rib.h
"#include"if.h"#include"workqueue.h"#include"vrf.h"#include"routemap.h"#include"
vty.h"#include"zclient.h"#include"zebra/zebra_ns.h"#include"zebra/zebra_pw.h"//#
include"zebra/zebra_pbr.h"/*Defaultportinformation.*/#defineZEBRA_VTY_PORT2601/*
Defaultconfigurationfilename.*/#defineDEFAULT_CONFIG_FILE"zebra.conf"#defineZEBR
A_RMAP_DEFAULT_UPDATE_TIMER5/*disabledbydefault*//*Clientstructure.*/structzserv
{/*Clientfiledescriptor.*/intsock;/*Input/outputbuffertotheclient.*/structstream
_fifo*ibuf_fifo;structstream_fifo*obuf_fifo;/*PrivateI/Obuffers*/structstream*ib
uf_work;structstream*obuf_work;/*Bufferofdatawaitingtobewrittentoclient.*/struct
buffer*wb;/*Threadsforread/write.*/structthread*t_read;structthread*t_write;/*Th
readfordelayedclose.*/structthread*t_suicide;/*defaultroutingtablethisclientmung
es*/intrtm_table;/*Thisclient'sredistributeflag.*/structredist_protomi_redist[AF
I_MAX][ZEBRA_ROUTE_MAX];vrf_bitmap_tredist[AFI_MAX][ZEBRA_ROUTE_MAX];/*Redistrib
utedefaultrouteflag.*/vrf_bitmap_tredist_default;/*Interfaceinformation.*/vrf_bi
tmap_tifinfo;/*Router-idinformation.*/vrf_bitmap_tridinfo;boolnotify_owner;/*cli
ent'sprotocol*/uint8_tproto;unsignedshortinstance;uint8_tis_synchronous;/*Statis
tics*/uint32_tredist_v4_add_cnt;uint32_tredist_v4_del_cnt;uint32_tredist_v6_add_
cnt;uint32_tredist_v6_del_cnt;uint32_tv4_route_add_cnt;uint32_tv4_route_upd8_cnt
;uint32_tv4_route_del_cnt;uint32_tv6_route_add_cnt;uint32_tv6_route_del_cnt;uint
32_tv6_route_upd8_cnt;uint32_tconnected_rt_add_cnt;uint32_tconnected_rt_del_cnt;
uint32_tifup_cnt;uint32_tifdown_cnt;uint32_tifadd_cnt;uint32_tifdel_cnt;uint32_t
if_bfd_cnt;uint32_tbfd_peer_add_cnt;uint32_tbfd_peer_upd8_cnt;uint32_tbfd_peer_d
el_cnt;uint32_tbfd_peer_replay_cnt;uint32_tvrfadd_cnt;uint32_tvrfdel_cnt;uint32_
tif_vrfchg_cnt;uint32_tbfd_client_reg_cnt;uint32_tvniadd_cnt;uint32_tvnidel_cnt;
uint32_tl3vniadd_cnt;uint32_tl3vnidel_cnt;uint32_tmacipadd_cnt;uint32_tmacipdel_
cnt;uint32_tprefixadd_cnt;uint32_tprefixdel_cnt;time_tconnect_time;time_tlast_re
ad_time;time_tlast_write_time;time_tnh_reg_time;time_tnh_dereg_time;time_tnh_las
t_upd_time;intlast_read_cmd;intlast_write_cmd;};#defineZAPI_HANDLER_ARGS\structz
serv*client,structzmsghdr*hdr,structstream*msg,\structzebra_vrf*zvrf/*Zebrainsta
nce*/structzebra_t{/*Threadmaster*/structthread_master*master;structlist*client_
list;/*defaulttable*/uint32_trtm_table_default;/*ribworkqueue*/#defineZEBRA_RIB_
PROCESS_HOLD_TIME10structwork_queue*ribq;structmeta_queue*mq;/*LSPworkqueue*/str
uctwork_queue*lsp_process_q;#defineZEBRA_ZAPI_PACKETS_TO_PROCESS10uint32_tpacket
s_to_process;};externstructzebra_tzebrad;externunsignedintmultipath_num;/*Protot
ypes.*/externvoidzserv_init(void);externvoidzebra_zserv_socket_init(char*path);e
xternintzsend_vrf_add(structzserv*,structzebra_vrf*);externintzsend_vrf_delete(s
tructzserv*,structzebra_vrf*);externintzsend_interface_add(structzserv*,structin
terface*);externintzsend_interface_delete(structzserv*,structinterface*);externi
ntzsend_interface_addresses(structzserv*,structinterface*);externintzsend_interf
ace_address(int,structzserv*,structinterface*,structconnected*);externvoidnbr_co
nnected_add_ipv6(structinterface*,structin6_addr*);externvoidnbr_connected_delet
e_ipv6(structinterface*,structin6_addr*);externintzsend_interface_update(int,str
uctzserv*,structinterface*);externintzsend_redistribute_route(int,structzserv*,s
tructprefix*,structprefix*,structroute_entry*);externintzsend_router_id_update(s
tructzserv*,structprefix*,vrf_id_t);externintzsend_interface_vrf_update(structzs
erv*,structinterface*,vrf_id_t);externintzsend_interface_link_params(structzserv
*,structinterface*);externintzsend_pw_update(structzserv*,structzebra_pw*);exter
nintzsend_route_notify_owner(structroute_entry*re,structprefix*p,enumzapi_route_
notify_ownernote);structzebra_pbr_rule;externvoidzsend_rule_notify_owner(structz
ebra_pbr_rule*rule,enumzapi_rule_notify_ownernote);externvoidzserv_nexthop_num_w
arn(constchar*,conststructprefix*,constunsignedint);externintzebra_server_send_m
essage(structzserv*client,structstream*msg);externstructzserv*zebra_find_client(
uint8_tproto,unsignedshortinstance);#ifdefined(HANDLE_ZAPI_FUZZING)externvoidzse
rv_read_file(char*input);#endif#endif/*_ZEBRA_ZEBRA_H*/