/**PIMforQuagga*Copyright(C)2008EvertondaSilvaMarques**Thisprogramisfreesoftware
;youcanredistributeitand/ormodify*itunderthetermsoftheGNUGeneralPublicLicenseasp
ublishedby*theFreeSoftwareFoundation;eitherversion2oftheLicense,or*(atyouroption
)anylaterversion.**Thisprogramisdistributedinthehopethatitwillbeuseful,but*WITHO
UTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTIC
ULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavereceived
acopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,w
ritetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-130
1USA*/#include<zebra.h>#include"if.h"#include"log.h"#include"prefix.h"#include"v
ty.h"#include"plist.h"#include"pimd.h"#include"pim_vty.h"#include"pim_pim.h"#inc
lude"pim_msg.h"#include"pim_util.h"#include"pim_str.h"#include"pim_iface.h"#incl
ude"pim_rp.h"#include"pim_rpf.h"#include"pim_register.h"#include"pim_jp_agg.h"#i
nclude"pim_oil.h"voidpim_msg_build_header(uint8_t*pim_msg,size_tpim_msg_size,uin
t8_tpim_msg_type){structpim_msg_header*header=(structpim_msg_header*)pim_msg;/**
Writeheader*/header->ver=PIM_PROTO_VERSION;header->type=pim_msg_type;header->res
erved=0;header->checksum=0;/**ThechecksumforRegistersisdoneonlyonthefirst8byteso
fthe*packet,*includingthePIMheaderandthenext4bytes,excludingthedata*packetportio
n*/if(pim_msg_type==PIM_MSG_TYPE_REGISTER)header->checksum=in_cksum(pim_msg,PIM_
MSG_REGISTER_LEN);elseheader->checksum=in_cksum(pim_msg,pim_msg_size);}uint8_t*p
im_msg_addr_encode_ipv4_ucast(uint8_t*buf,structin_addraddr){buf[0]=PIM_MSG_ADDR
ESS_FAMILY_IPV4;/*addrfamily*/buf[1]='\0';/*nativeencoding*/memcpy(buf+2,&addr,s
izeof(structin_addr));returnbuf+PIM_ENCODED_IPV4_UCAST_SIZE;}uint8_t*pim_msg_add
r_encode_ipv4_group(uint8_t*buf,structin_addraddr){buf[0]=PIM_MSG_ADDRESS_FAMILY
_IPV4;/*addrfamily*/buf[1]='\0';/*nativeencoding*/buf[2]='\0';/*reserved*/buf[3]
=32;/*masklen*/memcpy(buf+4,&addr,sizeof(structin_addr));returnbuf+PIM_ENCODED_I
PV4_GROUP_SIZE;}uint8_t*pim_msg_addr_encode_ipv4_source(uint8_t*buf,structin_add
raddr,uint8_tbits){buf[0]=PIM_MSG_ADDRESS_FAMILY_IPV4;/*addrfamily*/buf[1]='\0';
/*nativeencoding*/buf[2]=bits;buf[3]=32;/*masklen*/memcpy(buf+4,&addr,sizeof(str
uctin_addr));returnbuf+PIM_ENCODED_IPV4_SOURCE_SIZE;}/**Forthegiven'structpim_jp
_sources'list*determinethesize_titwouldtakeup.*/size_tpim_msg_get_jp_group_size(
structlist*sources){structpim_jp_sources*js;size_tsize=0;if(!sources)return0;siz
e+=sizeof(structpim_encoded_group_ipv4);size+=4;//Joinedsources(2)+PrunedSources
(2)size+=sizeof(structpim_encoded_source_ipv4)*sources->count;js=listgetdata(lis
thead(sources));if(js&&js->up->sg.src.s_addr==INADDR_ANY){structpim_upstream*chi
ld,*up;structlistnode*up_node;up=js->up;if(PIM_DEBUG_PIM_PACKETS)zlog_debug("%s:
Considering(%s)childrenfor(S,G,rpt)prune",__PRETTY_FUNCTION__,up->sg_str);for(AL
L_LIST_ELEMENTS_RO(up->sources,up_node,child)){if(child->sptbit==PIM_UPSTREAM_SP
TBIT_TRUE){if(!pim_rpf_is_same(&up->rpf,&child->rpf)){size+=sizeof(structpim_enc
oded_source_ipv4);PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(child->flags);if(PIM_D
EBUG_PIM_PACKETS)zlog_debug("%s:SPTBitandRPF'(%s)!=RPF'(S,G):AddPrune(%s,rpt)toc
ompoundmessage",__PRETTY_FUNCTION__,up->sg_str,child->sg_str);}elseif(PIM_DEBUG_
PIM_PACKETS)zlog_debug("%s:SPTBitandRPF'(%s)==RPF'(S,G):NotaddingPrunefor(%s,rpt
)",__PRETTY_FUNCTION__,up->sg_str,child->sg_str);}elseif(pim_upstream_is_sg_rpt(
child)){if(pim_upstream_empty_inherited_olist(child)){size+=sizeof(structpim_enc
oded_source_ipv4);PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(child->flags);if(PIM_D
EBUG_PIM_PACKETS)zlog_debug("%s:inherited_olist(%s,rpt)isNULL,AddPrunetocompound
message",__PRETTY_FUNCTION__,child->sg_str);}elseif(!pim_rpf_is_same(&up->rpf,&c
hild->rpf)){size+=sizeof(structpim_encoded_source_ipv4);PIM_UPSTREAM_FLAG_SET_SE
ND_SG_RPT_PRUNE(child->flags);if(PIM_DEBUG_PIM_PACKETS)zlog_debug("%s:RPF'(%s)!=
RPF'(%s,rpt),AddPrunetocompoundmessage",__PRETTY_FUNCTION__,up->sg_str,child->sg
_str);}elseif(PIM_DEBUG_PIM_PACKETS)zlog_debug("%s:RPF'(%s)==RPF'(%s,rpt),Donota
ddPrunetocompoundmessage",__PRETTY_FUNCTION__,up->sg_str,child->sg_str);}elseif(
PIM_DEBUG_PIM_PACKETS)zlog_debug("%s:SPTbitisnotsetfor(%s)",__PRETTY_FUNCTION__,
child->sg_str);}}returnsize;}size_tpim_msg_build_jp_groups(structpim_jp_groups*g
rp,structpim_jp_agg_group*sgs,size_tsize){structlistnode*node,*nnode;structpim_j
p_sources*source;structpim_upstream*up=NULL;structin_addrstosend;uint8_tbits;uin
t8_ttgroups=0;memset(grp,0,size);pim_msg_addr_encode_ipv4_group((uint8_t*)&grp->
g,sgs->group);for(ALL_LIST_ELEMENTS(sgs->sources,node,nnode,source)){/*numberofj
oined/prunedsources*/if(source->is_join)grp->joins++;elsegrp->prunes++;if(source
->up->sg.src.s_addr==INADDR_ANY){structpim_instance*pim=source->up->channel_oil-
>pim;structpim_rpf*rpf=pim_rp_g(pim,source->up->sg.grp);bits=PIM_ENCODE_SPARSE_B
IT|PIM_ENCODE_WC_BIT|PIM_ENCODE_RPT_BIT;stosend=rpf->rpf_addr.u.prefix4;/*OnlySe
ndSGRptincaseof*,GJoin*/if(source->is_join)up=source->up;}else{bits=PIM_ENCODE_S
PARSE_BIT;stosend=source->up->sg.src;}pim_msg_addr_encode_ipv4_source((uint8_t*)
&grp->s[tgroups],stosend,bits);tgroups++;}if(up){structpim_upstream*child;for(AL
L_LIST_ELEMENTS(up->sources,node,nnode,child)){if(PIM_UPSTREAM_FLAG_TEST_SEND_SG
_RPT_PRUNE(child->flags)){pim_msg_addr_encode_ipv4_source((uint8_t*)&grp->s[tgro
ups],child->sg.src,PIM_ENCODE_SPARSE_BIT|PIM_ENCODE_RPT_BIT);tgroups++;PIM_UPSTR
EAM_FLAG_UNSET_SEND_SG_RPT_PRUNE(child->flags);grp->prunes++;}}}grp->joins=htons
(grp->joins);grp->prunes=htons(grp->prunes);returnsize;}