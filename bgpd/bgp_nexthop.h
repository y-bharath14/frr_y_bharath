/*BGPnexthopscan*Copyright(C)2000KunihiroIshiguro**ThisfileispartofGNUZebra.**GN
UZebraisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGen
eralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(atyou
roption)any*laterversion.**GNUZebraisdistributedinthehopethatitwillbeuseful,but*
WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAP
ARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhaverec
eivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;if
not,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA0211
0-1301USA*/#ifndef_QUAGGA_BGP_NEXTHOP_H#define_QUAGGA_BGP_NEXTHOP_H#include"if.h
"#include"queue.h"#include"prefix.h"#defineNEXTHOP_FAMILY(nexthop_len)\(((nextho
p_len)==4||(nexthop_len)==12\?AF_INET\:((nexthop_len)==16||(nexthop_len)==24\||(
nexthop_len)==48\?AF_INET6\:AF_UNSPEC)))#defineBGP_MP_NEXTHOP_FAMILYNEXTHOP_FAMI
LY/*BGPnexthopcachevaluestructure.*/structbgp_nexthop_cache{/*IGProute'smetric.*
/uint32_tmetric;/*Nexthopnumberandnexthoplinkedlist.*/uint8_tnexthop_num;structn
exthop*nexthop;time_tlast_update;uint16_tflags;#defineBGP_NEXTHOP_VALID(1<<0)#de
fineBGP_NEXTHOP_REGISTERED(1<<1)#defineBGP_NEXTHOP_CONNECTED(1<<2)#defineBGP_NEX
THOP_PEER_NOTIFIED(1<<3)#defineBGP_STATIC_ROUTE(1<<4)#defineBGP_STATIC_ROUTE_EXA
CT_MATCH(1<<5)uint16_tchange_flags;#defineBGP_NEXTHOP_CHANGED(1<<0)#defineBGP_NE
XTHOP_METRIC_CHANGED(1<<1)#defineBGP_NEXTHOP_CONNECTED_CHANGED(1<<2)structbgp_no
de*node;void*nht_info;/*InBGP,peersession*/LIST_HEAD(path_list,bgp_info)paths;un
signedintpath_count;structbgp*bgp;};/*BGPownaddressstructure*/structbgp_addr{str
uctin_addraddr;intrefcnt;};/*Owntunnel-ipaddressstructure*/structtip_addr{struct
in_addraddr;intrefcnt;};externintbgp_nexthop_lookup(afi_t,structpeer*peer,struct
bgp_info*,int*,int*);externvoidbgp_connected_add(structbgp*bgp,structconnected*c
);externvoidbgp_connected_delete(structbgp*bgp,structconnected*c);externintbgp_s
ubgrp_multiaccess_check_v4(structin_addrnexthop,structupdate_subgroup*subgrp);ex
ternintbgp_multiaccess_check_v4(structin_addr,structpeer*);externintbgp_config_w
rite_scan_time(structvty*);externintbgp_nexthop_self(structbgp*,structin_addr);e
xternstructbgp_nexthop_cache*bnc_new(void);externvoidbnc_free(structbgp_nexthop_
cache*bnc);externvoidbnc_nexthop_free(structbgp_nexthop_cache*bnc);externchar*bn
c_str(structbgp_nexthop_cache*bnc,char*buf,intsize);externvoidbgp_scan_init(stru
ctbgp*bgp);externvoidbgp_scan_finish(structbgp*bgp);externvoidbgp_scan_vty_init(
void);externvoidbgp_address_init(structbgp*bgp);externvoidbgp_address_destroy(st
ructbgp*bgp);externvoidbgp_tip_add(structbgp*bgp,structin_addr*tip);externvoidbg
p_tip_del(structbgp*bgp,structin_addr*tip);externvoidbgp_tip_hash_init(structbgp
*bgp);externvoidbgp_tip_hash_destroy(structbgp*bgp);#endif/*_QUAGGA_BGP_NEXTHOP_
H*/