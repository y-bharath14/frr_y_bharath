/**Kernelroutingtableupdatesbyroutingsocket.*Copyright(C)1997,98KunihiroIshiguro
**ThisfileispartofGNUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/ormo
difyit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFou
ndation;eitherversion2,or(atyouroption)any*laterversion.**GNUZebraisdistributedi
nthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyo
f*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicensefo
rmoredetails.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*witht
hisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51Fran
klinSt,FifthFloor,Boston,MA02110-1301USA*/#include<zebra.h>#ifndefHAVE_NETLINK#i
fdef__OpenBSD__#include<netmpls/mpls.h>#endif#include"if.h"#include"prefix.h"#in
clude"sockunion.h"#include"log.h"#include"privs.h"#include"vxlan.h"#include"zebr
a/debug.h"#include"zebra/rib.h"#include"zebra/rt.h"#include"zebra/kernel_socket.
h"#include"zebra/zebra_mpls.h"externstructzebra_privs_tzserv_privs;#ifdefHAVE_ST
RUCT_SOCKADDR_IN_SIN_LEN/*Adjustnetmasksocketlength.Returnvalueisaadjustedsin_le
nvalue.*/staticintsin_masklen(structin_addrmask){char*p,*lim;intlen;structsockad
dr_insin;if(mask.s_addr==0)returnsizeof(long);sin.sin_addr=mask;len=sizeof(struc
tsockaddr_in);lim=(char*)&sin.sin_addr;p=lim+sizeof(sin.sin_addr);while(*--p==0&
&p>=lim)len--;returnlen;}#endif/*HAVE_STRUCT_SOCKADDR_IN_SIN_LEN*/#ifdef__OpenBS
D__staticintkernel_rtm_add_labels(structmpls_label_stack*nh_label,structsockaddr
_mpls*smpls){if(nh_label->num_labels>1){zlog_warn("%s:can'tpush%ulabelsat""once(
maximumis1)",__func__,nh_label->num_labels);return-1;}memset(smpls,0,sizeof(*smp
ls));smpls->smpls_len=sizeof(*smpls);smpls->smpls_family=AF_MPLS;smpls->smpls_la
bel=htonl(nh_label->label[0]<<MPLS_LABEL_OFFSET);return0;}#endif/*Interfacebetwe
enzebramessageandrtmmessage.*/staticintkernel_rtm_ipv4(intcmd,structprefix*p,str
uctroute_entry*re){structsockaddr_in*mask=NULL;structsockaddr_insin_dest,sin_mas
k,sin_gate;#ifdef__OpenBSD__structsockaddr_mplssmpls;#endifunionsockunion*smplsp
=NULL;structnexthop*nexthop;intnexthop_num=0;ifindex_tifindex=0;intgate=0;interr
or;charprefix_buf[PREFIX_STRLEN];enumblackhole_typebh_type=BLACKHOLE_UNSPEC;if(I
S_ZEBRA_DEBUG_RIB)prefix2str(p,prefix_buf,sizeof(prefix_buf));memset(&sin_dest,0
,sizeof(structsockaddr_in));sin_dest.sin_family=AF_INET;#ifdefHAVE_STRUCT_SOCKAD
DR_IN_SIN_LENsin_dest.sin_len=sizeof(structsockaddr_in);#endif/*HAVE_STRUCT_SOCK
ADDR_IN_SIN_LEN*/sin_dest.sin_addr=p->u.prefix4;memset(&sin_mask,0,sizeof(struct
sockaddr_in));memset(&sin_gate,0,sizeof(structsockaddr_in));sin_gate.sin_family=
AF_INET;#ifdefHAVE_STRUCT_SOCKADDR_IN_SIN_LENsin_gate.sin_len=sizeof(structsocka
ddr_in);#endif/*HAVE_STRUCT_SOCKADDR_IN_SIN_LEN*//*Makegateway.*/for(ALL_NEXTHOP
S(re->ng,nexthop)){if(CHECK_FLAG(nexthop->flags,NEXTHOP_FLAG_RECURSIVE))continue
;gate=0;chargate_buf[INET_ADDRSTRLEN]="NULL";/**XXXWeneedtorefrainfromkerneloper
ationsinsomecases,*butthisifstatementseemsoverlycautious-whatabout*otherthanADDa
ndDELETE?*/if((cmd==RTM_ADD&&NEXTHOP_IS_ACTIVE(nexthop->flags))||(cmd==RTM_DELET
E&&CHECK_FLAG(nexthop->flags,NEXTHOP_FLAG_FIB))){if(nexthop->type==NEXTHOP_TYPE_
IPV4||nexthop->type==NEXTHOP_TYPE_IPV4_IFINDEX){sin_gate.sin_addr=nexthop->gate.
ipv4;gate=1;}if(nexthop->type==NEXTHOP_TYPE_IFINDEX||nexthop->type==NEXTHOP_TYPE
_IPV4_IFINDEX)ifindex=nexthop->ifindex;if(nexthop->type==NEXTHOP_TYPE_BLACKHOLE)
{structin_addrloopback;loopback.s_addr=htonl(INADDR_LOOPBACK);sin_gate.sin_addr=
loopback;bh_type=nexthop->bh_type;gate=1;}if(gate&&p->prefixlen==32)mask=NULL;el
se{masklen2ip(p->prefixlen,&sin_mask.sin_addr);sin_mask.sin_family=AF_INET;#ifde
fHAVE_STRUCT_SOCKADDR_IN_SIN_LENsin_mask.sin_len=sin_masklen(sin_mask.sin_addr);
#endif/*HAVE_STRUCT_SOCKADDR_IN_SIN_LEN*/mask=&sin_mask;}#ifdef__OpenBSD__if(nex
thop->nh_label&&!kernel_rtm_add_labels(nexthop->nh_label,&smpls))continue;smplsp
=(unionsockunion*)&smpls;#endiferror=rtm_write(cmd,(unionsockunion*)&sin_dest,(u
nionsockunion*)mask,gate?(unionsockunion*)&sin_gate:NULL,smplsp,ifindex,bh_type,
re->metric);if(IS_ZEBRA_DEBUG_RIB){if(!gate){zlog_debug("%s:%s:attention!gatenot
foundforre%p",__func__,prefix_buf,re);route_entry_dump(p,NULL,re);}elseinet_ntop
(AF_INET,&sin_gate.sin_addr,gate_buf,INET_ADDRSTRLEN);}switch(error){/*Weonlyfla
gnexthopsasbeinginFIBifrtm_write()*diditswork.*/caseZEBRA_ERR_NOERROR:nexthop_nu
m++;if(IS_ZEBRA_DEBUG_RIB)zlog_debug("%s:%s:successfullydidNH%s",__func__,prefix
_buf,gate_buf);break;/*Theonlyvalidcaseforthiserroriskernel's*failuretoinstall*a
multipathroute,whichiscommonforFreeBSD.This*shouldbe*ignoredsilently,butloggedas
anerrorotherwise.*/caseZEBRA_ERR_RTEXIST:if(cmd!=RTM_ADD)zlog_err("%s:rtm_write(
)returned%dforcommand%d",__func__,error,cmd);continue;break;/*GiventhatourNEXTHO
P_FLAG_FIBmatchesrealkernel*FIB,itisn't*normaltogetanyothermessagesinANYcase.*/c
aseZEBRA_ERR_RTNOEXIST:caseZEBRA_ERR_RTUNREACH:default:zlog_err("%s:%s:rtm_write
()unexpectedlyreturned%dforcommand%s",__func__,prefix2str(p,prefix_buf,sizeof(pr
efix_buf)),error,lookup_msg(rtm_type_str,cmd,NULL));break;}}/*if(cmdandflagsmake
sense)*/elseif(IS_ZEBRA_DEBUG_RIB)zlog_debug("%s:oddcommand%sforflags%d",__func_
_,lookup_msg(rtm_type_str,cmd,NULL),nexthop->flags);}/*for(ALL_NEXTHOPS(...))*//
*Iftherewasnousefulnexthop,thencomplain.*/if(nexthop_num==0&&IS_ZEBRA_DEBUG_KERN
EL)zlog_debug("%s:NousefulnexthopswerefoundinRIBentry%p",__func__,re);return0;/*
XXX*/}#ifdefSIN6_LEN/*Calculatesin6_lenvaluefornetmasksocketvalue.*/staticintsin
6_masklen(structin6_addrmask){structsockaddr_in6sin6;char*p,*lim;intlen;if(IN6_I
S_ADDR_UNSPECIFIED(&mask))returnsizeof(long);sin6.sin6_addr=mask;len=sizeof(stru
ctsockaddr_in6);lim=(char*)&sin6.sin6_addr;p=lim+sizeof(sin6.sin6_addr);while(*-
-p==0&&p>=lim)len--;returnlen;}#endif/*SIN6_LEN*//*Interfacebetweenzebramessagea
ndrtmmessage.*/staticintkernel_rtm_ipv6(intcmd,structprefix*p,structroute_entry*
re){structsockaddr_in6*mask;structsockaddr_in6sin_dest,sin_mask,sin_gate;#ifdef_
_OpenBSD__structsockaddr_mplssmpls;#endifunionsockunion*smplsp=NULL;structnextho
p*nexthop;intnexthop_num=0;ifindex_tifindex=0;intgate=0;interror;enumblackhole_t
ypebh_type=BLACKHOLE_UNSPEC;memset(&sin_dest,0,sizeof(structsockaddr_in6));sin_d
est.sin6_family=AF_INET6;#ifdefSIN6_LENsin_dest.sin6_len=sizeof(structsockaddr_i
n6);#endif/*SIN6_LEN*/sin_dest.sin6_addr=p->u.prefix6;memset(&sin_mask,0,sizeof(
structsockaddr_in6));memset(&sin_gate,0,sizeof(structsockaddr_in6));sin_gate.sin
6_family=AF_INET6;#ifdefHAVE_STRUCT_SOCKADDR_IN_SIN_LENsin_gate.sin6_len=sizeof(
structsockaddr_in6);#endif/*HAVE_STRUCT_SOCKADDR_IN_SIN_LEN*//*Makegateway.*/for
(ALL_NEXTHOPS(re->ng,nexthop)){if(CHECK_FLAG(nexthop->flags,NEXTHOP_FLAG_RECURSI
VE))continue;gate=0;if((cmd==RTM_ADD&&NEXTHOP_IS_ACTIVE(nexthop->flags))||(cmd==
RTM_DELETE)){if(nexthop->type==NEXTHOP_TYPE_IPV6||nexthop->type==NEXTHOP_TYPE_IP
V6_IFINDEX){sin_gate.sin6_addr=nexthop->gate.ipv6;gate=1;}if(nexthop->type==NEXT
HOP_TYPE_IFINDEX||nexthop->type==NEXTHOP_TYPE_IPV6_IFINDEX)ifindex=nexthop->ifin
dex;if(nexthop->type==NEXTHOP_TYPE_BLACKHOLE)bh_type=nexthop->bh_type;}/*Underka
mesetinterfaceindextolinklocaladdress.*/#ifdefKAME#defineSET_IN6_LINKLOCAL_IFIND
EX(a,i)\do{\(a).s6_addr[2]=((i)>>8)&0xff;\(a).s6_addr[3]=(i)&0xff;\}while(0)if(g
ate&&IN6_IS_ADDR_LINKLOCAL(&sin_gate.sin6_addr))SET_IN6_LINKLOCAL_IFINDEX(sin_ga
te.sin6_addr,ifindex);#endif/*KAME*/if(gate&&p->prefixlen==128)mask=NULL;else{ma
sklen2ip6(p->prefixlen,&sin_mask.sin6_addr);sin_mask.sin6_family=AF_INET6;#ifdef
SIN6_LENsin_mask.sin6_len=sin6_masklen(sin_mask.sin6_addr);#endif/*SIN6_LEN*/mas
k=&sin_mask;}#ifdef__OpenBSD__if(nexthop->nh_label&&!kernel_rtm_add_labels(nexth
op->nh_label,&smpls))continue;smplsp=(unionsockunion*)&smpls;#endiferror=rtm_wri
te(cmd,(unionsockunion*)&sin_dest,(unionsockunion*)mask,gate?(unionsockunion*)&s
in_gate:NULL,smplsp,ifindex,bh_type,re->metric);(void)error;nexthop_num++;}/*Ift
hereisnousefulnexthopthenreturn.*/if(nexthop_num==0){if(IS_ZEBRA_DEBUG_KERNEL)zl
og_debug("kernel_rtm_ipv6():Nousefulnexthop.");return0;}return0;/*XXX*/}staticin
tkernel_rtm(intcmd,structprefix*p,structroute_entry*re){switch(PREFIX_FAMILY(p))
{caseAF_INET:returnkernel_rtm_ipv4(cmd,p,re);caseAF_INET6:returnkernel_rtm_ipv6(
cmd,p,re);}return0;}voidkernel_route_rib(structroute_node*rn,structprefix*p,stru
ctprefix*src_p,structroute_entry*old,structroute_entry*new){introute=0;if(src_p&
&src_p->prefixlen){zlog_err("routeadd:IPv6sourcedestroutesunsupported!");return;
}if(zserv_privs.change(ZPRIVS_RAISE))zlog_err("Can'traiseprivileges");if(old)rou
te|=kernel_rtm(RTM_DELETE,p,old);if(new)route|=kernel_rtm(RTM_ADD,p,new);if(zser
v_privs.change(ZPRIVS_LOWER))zlog_err("Can'tlowerprivileges");if(new){kernel_rou
te_rib_pass_fail(rn,p,new,(!route)?SOUTHBOUND_INSTALL_SUCCESS:SOUTHBOUND_INSTALL
_FAILURE);}else{kernel_route_rib_pass_fail(rn,p,old,(!route)?SOUTHBOUND_DELETE_S
UCCESS:SOUTHBOUND_DELETE_FAILURE);}}intkernel_neigh_update(intadd,intifindex,uin
t32_taddr,char*lla,intllalen,ns_id_tns_id){/*TODO*/return0;}externintkernel_get_
ipmr_sg_stats(structzebra_vrf*zvrf,void*mroute){return0;}intkernel_add_vtep(vni_
tvni,structinterface*ifp,structin_addr*vtep_ip){return0;}intkernel_del_vtep(vni_
tvni,structinterface*ifp,structin_addr*vtep_ip){return0;}intkernel_add_mac(struc
tinterface*ifp,vlanid_tvid,structethaddr*mac,structin_addrvtep_ip,uint8_tsticky)
{return0;}intkernel_del_mac(structinterface*ifp,vlanid_tvid,structethaddr*mac,st
ructin_addrvtep_ip,intlocal){return0;}intkernel_add_neigh(structinterface*ifp,st
ructipaddr*ip,structethaddr*mac){return0;}intkernel_del_neigh(structinterface*if
p,structipaddr*ip){return0;}externintkernel_interface_set_master(structinterface
*master,structinterface*slave){return0;}uint32_tkernel_get_speed(structinterface
*ifp){returnifp->speed;}#endif/*!HAVE_NETLINK*/