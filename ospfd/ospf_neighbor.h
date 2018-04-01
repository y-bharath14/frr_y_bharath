/**OSPFNeighborfunctions.*Copyright(C)1999,2000ToshiakiTakada**ThisfileispartofG
NUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/ormodify*itundertheterm
softheGNUGeneralPublicLicenseaspublished*bytheFreeSoftwareFoundation;eitherversi
on2,or(atyour*option)anylaterversion.**GNUZebraisdistributedinthehopethatitwillb
euseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYor
FITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Yous
houldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefi
leCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,B
oston,MA02110-1301USA*/#ifndef_ZEBRA_OSPF_NEIGHBOR_H#define_ZEBRA_OSPF_NEIGHBOR_
H#include<ospfd/ospf_packet.h>/*NeighborDataStructure*/structospf_neighbor{/*Thi
sneighbor'sparentospfinterface.*/structospf_interface*oi;/*OSPFneighborInformati
on*/uint8_tstate;/*NSMstatus.*/uint8_tdd_flags;/*DDbitflags.*/uint32_tdd_seqnum;
/*DDSequenceNumber.*//*NeighborInformationfromHello.*/structprefixaddress;/*Neig
hborInterfaceAddress.*/structin_addrsrc;/*Srcaddress.*/structin_addrrouter_id;/*
RouterID.*/uint8_toptions;/*Options.*/intpriority;/*RouterPriority.*/structin_ad
drd_router;/*DesignatedRouter.*/structin_addrbd_router;/*BackupDesignatedRouter.
*//*LastsentDatabaseDescriptionpacket.*/structospf_packet*last_send;/*Timestempw
henlastDatabaseDescriptionpacketwassent*/structtimevallast_send_ts;/*Lastreceive
dDatabseDescriptionpacket.*/struct{uint8_toptions;uint8_tflags;uint32_tdd_seqnum
;}last_recv;/*LSAdata.*/structospf_lsdbls_rxmt;structospf_lsdbdb_sum;structospf_
lsdbls_req;structospf_lsa*ls_req_last;uint32_tcrypt_seqnum;/*CryptographicSequen
ceNumber.*//*Timervalues.*/uint32_tv_inactivity;uint32_tv_db_desc;uint32_tv_ls_r
eq;uint32_tv_ls_upd;/*Threads.*/structthread*t_inactivity;structthread*t_db_desc
;structthread*t_ls_req;structthread*t_ls_upd;structthread*t_hello_reply;/*NBMAco
nfiguredneighbour*/structospf_nbr_nbma*nbr_nbma;/*Statistics*/structtimevalts_la
st_progress;/*lastadvanceofNSM*/structtimevalts_last_regress;/*lastregressiveNSM
change*/constchar*last_regress_str;/*EventwhichlastregressedNSM*/uint32_tstate_c
hange;/*NSMstatechangecounter*//*BFDinformation*/void*bfd_info;};/*Macros.*/#def
ineNBR_IS_DR(n)IPV4_ADDR_SAME(&n->address.u.prefix4,&n->d_router)#defineNBR_IS_B
DR(n)IPV4_ADDR_SAME(&n->address.u.prefix4,&n->bd_router)/*Prototypes.*/externstr
uctospf_neighbor*ospf_nbr_new(structospf_interface*);externvoidospf_nbr_free(str
uctospf_neighbor*);externvoidospf_nbr_delete(structospf_neighbor*);externintospf
_nbr_bidirectional(structin_addr*,structin_addr*,int);externvoidospf_nbr_self_re
set(structospf_interface*,structin_addr);externvoidospf_nbr_add_self(structospf_
interface*,structin_addr);externintospf_nbr_count(structospf_interface*,int);ext
ernintospf_nbr_count_opaque_capable(structospf_interface*);externstructospf_neig
hbor*ospf_nbr_get(structospf_interface*,structospf_header*,structip*,structprefi
x*);externstructospf_neighbor*ospf_nbr_lookup(structospf_interface*,structip*,st
ructospf_header*);externstructospf_neighbor*ospf_nbr_lookup_by_addr(structroute_
table*,structin_addr*);externstructospf_neighbor*ospf_nbr_lookup_by_routerid(str
uctroute_table*,structin_addr*);externvoidospf_renegotiate_optional_capabilities
(structospf*top);#endif/*_ZEBRA_OSPF_NEIGHBOR_H*/