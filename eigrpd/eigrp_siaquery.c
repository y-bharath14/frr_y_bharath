/**EIGRPSendingandReceivingEIGRPSIA-QueryPackets.*Copyright(C)2013-2014*Authors:
*DonnieSavage*JanJanovic*MatejPerina*PeterOrsag*PeterPaluch**ThisfileispartofGNU
Zebra.**GNUZebraisfreesoftware;youcanredistributeitand/ormodifyit*underthetermso
ftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion
2,or(atyouroption)any*laterversion.**GNUZebraisdistributedinthehopethatitwillbeu
seful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFI
TNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Yousho
uldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefile
COPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Bos
ton,MA02110-1301USA*/#include<zebra.h>#include"thread.h"#include"memory.h"#inclu
de"linklist.h"#include"prefix.h"#include"if.h"#include"table.h"#include"sockunio
n.h"#include"stream.h"#include"log.h"#include"sockopt.h"#include"checksum.h"#inc
lude"md5.h"#include"vty.h"#include"eigrpd/eigrp_structs.h"#include"eigrpd/eigrpd
.h"#include"eigrpd/eigrp_interface.h"#include"eigrpd/eigrp_neighbor.h"#include"e
igrpd/eigrp_packet.h"#include"eigrpd/eigrp_zebra.h"#include"eigrpd/eigrp_vty.h"#
include"eigrpd/eigrp_dump.h"#include"eigrpd/eigrp_macros.h"#include"eigrpd/eigrp
_topology.h"#include"eigrpd/eigrp_fsm.h"#include"eigrpd/eigrp_memory.h"/*EIGRPSI
A-QUERYreadfunction*/voideigrp_siaquery_receive(structeigrp*eigrp,structip*iph,s
tructeigrp_header*eigrph,structstream*s,structeigrp_interface*ei,intsize){struct
eigrp_neighbor*nbr;structTLV_IPv4_Internal_type*tlv;uint16_ttype;/*incrementstat
istics.*/ei->siaQuery_in++;/*getneighborstruct*/nbr=eigrp_nbr_get(ei,eigrph,iph)
;/*neighbormustbevalid,eigrp_nbr_getcreatesifnoneexisted*/assert(nbr);nbr->recv_
sequence_number=ntohl(eigrph->sequence);while(s->endp>s->getp){type=stream_getw(
s);if(type==EIGRP_TLV_IPv4_INT){structprefixdest_addr;stream_set_getp(s,s->getp-
sizeof(uint16_t));tlv=eigrp_read_ipv4_tlv(s);dest_addr.family=AFI_IP;dest_addr.u
.prefix4=tlv->destination;dest_addr.prefixlen=tlv->prefix_length;structeigrp_pre
fix_entry*dest=eigrp_topology_table_lookup_ipv4(eigrp->topology_table,&dest_addr
);/*Ifthedestinationexists(itshould,butonenever*know)*/if(dest!=NULL){structeigr
p_fsm_action_messagemsg;structeigrp_nexthop_entry*entry=eigrp_prefix_entry_looku
p(dest->entries,nbr);msg.packet_type=EIGRP_OPC_SIAQUERY;msg.eigrp=eigrp;msg.data
_type=EIGRP_INT;msg.adv_router=nbr;msg.metrics=tlv->metric;msg.entry=entry;msg.p
refix=dest;eigrp_fsm_event(&msg);}eigrp_IPv4_InternalTLV_free(tlv);}}eigrp_hello
_send_ack(nbr);}voideigrp_send_siaquery(structeigrp_neighbor*nbr,structeigrp_pre
fix_entry*pe){structeigrp_packet*ep;uint16_tlength=EIGRP_HEADER_LEN;ep=eigrp_pac
ket_new(nbr->ei->ifp->mtu,nbr);/*PrepareEIGRPINITUPDATEheader*/eigrp_packet_head
er_init(EIGRP_OPC_SIAQUERY,nbr->ei->eigrp,ep->s,0,nbr->ei->eigrp->sequence_numbe
r,0);//encodeAuthenticationTLV,ifneededif((nbr->ei->params.auth_type==EIGRP_AUTH
_TYPE_MD5)&&(nbr->ei->params.auth_keychain!=NULL)){length+=eigrp_add_authTLV_MD5
_to_stream(ep->s,nbr->ei);}length+=eigrp_add_internalTLV_to_stream(ep->s,pe);if(
(nbr->ei->params.auth_type==EIGRP_AUTH_TYPE_MD5)&&(nbr->ei->params.auth_keychain
!=NULL)){eigrp_make_md5_digest(nbr->ei,ep->s,EIGRP_AUTH_UPDATE_FLAG);}/*EIGRPChe
cksum*/eigrp_packet_checksum(nbr->ei,ep->s,length);ep->length=length;ep->dst.s_a
ddr=nbr->src.s_addr;/*Thisacknumberweawaitfromneighbor*/ep->sequence_number=nbr-
>ei->eigrp->sequence_number;if(nbr->state==EIGRP_NEIGHBOR_UP){/*Putpackettoretra
nsmissionqueue*/eigrp_fifo_push(nbr->retrans_queue,ep);if(nbr->retrans_queue->co
unt==1){eigrp_send_packet_reliably(nbr);}}elseeigrp_packet_free(ep);}