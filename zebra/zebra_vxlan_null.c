/**ZebraVxLAN(EVPN)*Copyright(C)2016,2017CumulusNetworks,Inc.**ThisfileispartofF
RR.**FRRisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNUG
eneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(aty
ouroption)any*laterversion.**FRRisdistributedinthehopethatitwillbeuseful,but*WIT
HOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPART
ICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavereceiv
edacopyoftheGNUGeneralPublicLicense*alongwithFRR;seethefileCOPYING.Ifnot,writeto
theFree*SoftwareFoundation,Inc.,59TemplePlace-Suite330,Boston,MA*02111-1307,USA.
*/#include<zebra.h>#include"if.h"#include"zebra/debug.h"#include"zebra/zserv.h"#
include"zebra/rib.h"#include"zebra/zebra_vrf.h"#include"zebra/zebra_l2.h"#includ
e"zebra/zebra_vxlan.h"voidzebra_vxlan_print_macs_vni(structvty*vty,structzebra_v
rf*zvrf,vni_tvni){}voidzebra_vxlan_print_macs_all_vni(structvty*vty,structzebra_
vrf*zvrf){}voidzebra_vxlan_print_macs_all_vni_vtep(structvty*vty,structzebra_vrf
*zvrf,structin_addrvtep_ip){}voidzebra_vxlan_print_specific_mac_vni(structvty*vt
y,structzebra_vrf*zvrf,vni_tvni,structethaddr*mac){}voidzebra_vxlan_print_macs_v
ni_vtep(structvty*vty,structzebra_vrf*zvrf,vni_tvni,structin_addrvtep_ip){}voidz
ebra_vxlan_print_neigh_vni(structvty*vty,structzebra_vrf*zvrf,vni_tvni){}voidzeb
ra_vxlan_print_neigh_all_vni(structvty*vty,structzebra_vrf*zvrf){}voidzebra_vxla
n_print_specific_neigh_vni(structvty*vty,structzebra_vrf*zvrf,vni_tvni,structipa
ddr*ip){}voidzebra_vxlan_print_neigh_vni_vtep(structvty*vty,structzebra_vrf*zvrf
,vni_tvni,structin_addrvtep_ip){}voidzebra_vxlan_print_vni(structvty*vty,structz
ebra_vrf*zvrf,vni_tvni){}voidzebra_vxlan_print_vnis(structvty*vty,structzebra_vr
f*zvrf){}voidzebra_vxlan_print_evpn(structvty*vty,uint8_tuj){}voidzebra_vxlan_pr
int_rmacs_l3vni(structvty*,vni_t,uint8_t){}voidzebra_vxlan_print_rmacs_all_l3vni
(structvty*,uint8_t){}voidzebra_vxlan_print_nh_l3vni(structvty*,vni_t,uint8_t){}
voidzebra_vxlan_print_nh_all_l3vni(structvty*,uint8_t){}voidzebra_vxlan_print_l3
vni(structvty*vty,vni_tvni){}intzebra_vxlan_svi_up(structinterface*ifp,structint
erface*link_if){return0;}intzebra_vxlan_svi_down(structinterface*ifp,structinter
face*link_if){return0;}intzebra_vxlan_remote_macip_add(structzserv*client,intsoc
k,unsignedshortlength,structzebra_vrf*zvrf){return0;}intzebra_vxlan_remote_macip
_del(structzserv*client,intsock,unsignedshortlength,structzebra_vrf*zvrf){return
0;}intzebra_vxlan_local_mac_add_update(structinterface*ifp,structinterface*br_if
,structethaddr*mac,vlanid_tvid,uint8_tsticky){return0;}intzebra_vxlan_local_mac_
del(structinterface*ifp,structinterface*br_if,structethaddr*mac,vlanid_tvid){ret
urn0;}intzebra_vxlan_check_readd_remote_mac(structinterface*ifp,structinterface*
br_if,structethaddr*mac,vlanid_tvid){return0;}intzebra_vxlan_check_del_local_mac
(structinterface*ifp,structinterface*br_if,structethaddr*mac,vlanid_tvid){return
0;}intzebra_vxlan_if_up(structinterface*ifp){return0;}intzebra_vxlan_if_down(str
uctinterface*ifp){return0;}intzebra_vxlan_if_add(structinterface*ifp){return0;}i
ntzebra_vxlan_if_update(structinterface*ifp,uint16_tchgflags){return0;}intzebra_
vxlan_if_del(structinterface*ifp){return0;}intzebra_vxlan_remote_vtep_add(struct
zserv*client,intsock,unsignedshortlength,structzebra_vrf*zvrf){return0;}intzebra
_vxlan_remote_vtep_del(structzserv*client,intsock,unsignedshortlength,structzebr
a_vrf*zvrf){return0;}intzebra_vxlan_advertise_all_vni(structzserv*client,intsock
,unsignedshortlength,structzebra_vrf*zvrf){return0;}voidzebra_vxlan_init_tables(
structzebra_vrf*zvrf){}voidzebra_vxlan_close_tables(structzebra_vrf*zvrf){}voidz
ebra_vxlan_cleanup_tables(structzebra_vrf*zvrf){}