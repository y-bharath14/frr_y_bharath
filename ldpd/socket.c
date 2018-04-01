/*$OpenBSD$*//**Copyright(c)2016RenatoWestphal<renato@openbsd.org>*Copyright(c)2
009MicheleMarchetto<michele@openbsd.org>*Copyright(c)2005ClaudioJeker<claudio@op
enbsd.org>*Copyright(c)2003,2004HenningBrauer<henning@openbsd.org>**Permissionto
use,copy,modify,anddistributethissoftwareforany*purposewithorwithoutfeeisherebyg
ranted,providedthattheabove*copyrightnoticeandthispermissionnoticeappearinallcop
ies.**THESOFTWAREISPROVIDED"ASIS"ANDTHEAUTHORDISCLAIMSALLWARRANTIES*WITHREGARDTO
THISSOFTWAREINCLUDINGALLIMPLIEDWARRANTIESOF*MERCHANTABILITYANDFITNESS.INNOEVENTS
HALLTHEAUTHORBELIABLEFOR*ANYSPECIAL,DIRECT,INDIRECT,ORCONSEQUENTIALDAMAGESORANYD
AMAGES*WHATSOEVERRESULTINGFROMLOSSOFUSE,DATAORPROFITS,WHETHERINAN*ACTIONOFCONTRA
CT,NEGLIGENCEOROTHERTORTIOUSACTION,ARISINGOUTOF*ORINCONNECTIONWITHTHEUSEORPERFOR
MANCEOFTHISSOFTWARE.*/#include<zebra.h>#include"ldpd.h"#include"ldpe.h"#include"
log.h"#include"lib/log.h"#include"privs.h"#include"sockopt.h"externstructzebra_p
rivs_tldpd_privs;externstructzebra_privs_tldpe_privs;intldp_create_socket(intaf,
enumsocket_typetype){intfd,domain,proto;unionldpd_addraddr;structsockaddr_storag
elocal_sa;#ifdef__OpenBSD__intopt;#endifintsave_errno;/*createsocket*/switch(typ
e){caseLDP_SOCKET_DISC:caseLDP_SOCKET_EDISC:domain=SOCK_DGRAM;proto=IPPROTO_UDP;
break;caseLDP_SOCKET_SESSION:domain=SOCK_STREAM;proto=IPPROTO_TCP;break;default:
fatalx("ldp_create_socket:unknownsockettype");}fd=socket(af,domain,proto);if(fd=
=-1){log_warn("%s:errorcreatingsocket",__func__);return(-1);}sock_set_nonblock(f
d);sockopt_v6only(af,fd);/*bindtoalocaladdress/port*/switch(type){caseLDP_SOCKET
_DISC:/*listenonalladdresses*/memset(&addr,0,sizeof(addr));memcpy(&local_sa,addr
2sa(af,&addr,LDP_PORT),sizeof(local_sa));break;caseLDP_SOCKET_EDISC:caseLDP_SOCK
ET_SESSION:addr=(ldp_af_conf_get(ldpd_conf,af))->trans_addr;memcpy(&local_sa,add
r2sa(af,&addr,LDP_PORT),sizeof(local_sa));/*ignoreanypossibleerror*/sock_set_bin
dany(fd,1);break;}if(ldpd_privs.change(ZPRIVS_RAISE))log_warn("%s:couldnotraisep
rivs",__func__);if(sock_set_reuse(fd,1)==-1){if(ldpd_privs.change(ZPRIVS_LOWER))
log_warn("%s:couldnotlowerprivs",__func__);close(fd);return(-1);}if(bind(fd,(str
uctsockaddr*)&local_sa,sockaddr_len((structsockaddr*)&local_sa))==-1){save_errno
=errno;if(ldpd_privs.change(ZPRIVS_LOWER))log_warn("%s:couldnotlowerprivs",__fun
c__);log_warnx("%s:errorbindingsocket:%s",__func__,safe_strerror(save_errno));cl
ose(fd);return(-1);}if(ldpd_privs.change(ZPRIVS_LOWER))log_warn("%s:couldnotlowe
rprivs",__func__);/*setoptions*/switch(af){caseAF_INET:if(sock_set_ipv4_tos(fd,I
PTOS_PREC_INTERNETCONTROL)==-1){close(fd);return(-1);}if(type==LDP_SOCKET_DISC){
if(sock_set_ipv4_mcast_ttl(fd,IP_DEFAULT_MULTICAST_TTL)==-1){close(fd);return(-1
);}if(sock_set_ipv4_mcast_loop(fd)==-1){close(fd);return(-1);}}if(type==LDP_SOCK
ET_DISC||type==LDP_SOCKET_EDISC){if(sock_set_ipv4_recvif(fd,1)==-1){close(fd);re
turn(-1);}#ifndefMSG_MCAST#ifdefined(HAVE_IP_PKTINFO)if(sock_set_ipv4_pktinfo(fd
,1)==-1){close(fd);return(-1);}#elifdefined(HAVE_IP_RECVDSTADDR)if(sock_set_ipv4
_recvdstaddr(fd,1)==-1){close(fd);return(-1);}#else#error"UnsupportedsocketAPI"#
endif#endif/*MSG_MCAST*/}if(type==LDP_SOCKET_SESSION){if(sock_set_ipv4_ucast_ttl
(fd,255)==-1){close(fd);return(-1);}}break;caseAF_INET6:if(sock_set_ipv6_dscp(fd
,IPTOS_PREC_INTERNETCONTROL)==-1){close(fd);return(-1);}if(type==LDP_SOCKET_DISC
){if(sock_set_ipv6_mcast_loop(fd)==-1){close(fd);return(-1);}if(sock_set_ipv6_mc
ast_hops(fd,255)==-1){close(fd);return(-1);}if(!(ldpd_conf->ipv6.flags&F_LDPD_AF
_NO_GTSM)){/*ignoreanypossibleerror*/sock_set_ipv6_minhopcount(fd,255);}}if(type
==LDP_SOCKET_DISC||type==LDP_SOCKET_EDISC){if(sock_set_ipv6_pktinfo(fd,1)==-1){c
lose(fd);return(-1);}}if(type==LDP_SOCKET_SESSION){if(sock_set_ipv6_ucast_hops(f
d,255)==-1){close(fd);return(-1);}}break;}switch(type){caseLDP_SOCKET_DISC:caseL
DP_SOCKET_EDISC:sock_set_recvbuf(fd);break;caseLDP_SOCKET_SESSION:if(listen(fd,L
DP_BACKLOG)==-1)log_warn("%s:errorlisteningonsocket",__func__);#ifdef__OpenBSD__
opt=1;if(setsockopt(fd,IPPROTO_TCP,TCP_MD5SIG,&opt,sizeof(opt))==-1){if(errno==E
NOPROTOOPT){/*systemw/omd5sig*/log_warnx("md5signotavailable,disabling");sysdep.
no_md5sig=1;}else{close(fd);return(-1);}}#endifbreak;}return(fd);}voidsock_set_n
onblock(intfd){intflags;if((flags=fcntl(fd,F_GETFL,0))==-1)fatal("fcntlF_GETFL")
;flags|=O_NONBLOCK;if((flags=fcntl(fd,F_SETFL,flags))==-1)fatal("fcntlF_SETFL");
}voidsock_set_cloexec(intfd){intflags;if((flags=fcntl(fd,F_GETFD,0))==-1)fatal("
fcntlF_GETFD");flags|=FD_CLOEXEC;if((flags=fcntl(fd,F_SETFD,flags))==-1)fatal("f
cntlF_SETFD");}voidsock_set_recvbuf(intfd){intbsize;bsize=65535;while(setsockopt
(fd,SOL_SOCKET,SO_RCVBUF,&bsize,sizeof(bsize))==-1)bsize/=2;}intsock_set_reuse(i
ntfd,intenable){if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&enable,sizeof(int))<0)
{log_warn("%s:errorsettingSO_REUSEADDR",__func__);return(-1);}return(0);}intsock
_set_bindany(intfd,intenable){#ifdefHAVE_SO_BINDANYif(ldpd_privs.change(ZPRIVS_R
AISE))log_warn("%s:couldnotraiseprivs",__func__);if(setsockopt(fd,SOL_SOCKET,SO_
BINDANY,&enable,sizeof(int))<0){if(ldpd_privs.change(ZPRIVS_LOWER))log_warn("%s:
couldnotlowerprivs",__func__);log_warn("%s:errorsettingSO_BINDANY",__func__);ret
urn(-1);}if(ldpd_privs.change(ZPRIVS_LOWER))log_warn("%s:couldnotlowerprivs",__f
unc__);return(0);#elifdefined(HAVE_IP_FREEBIND)if(setsockopt(fd,IPPROTO_IP,IP_FR
EEBIND,&enable,sizeof(int))<0){log_warn("%s:errorsettingIP_FREEBIND",__func__);r
eturn(-1);}return(0);#elselog_warnx("%s:missingSO_BINDANYandIP_FREEBIND,unableto
bind""toanonlocalIPaddress",__func__);return(-1);#endif/*HAVE_SO_BINDANY*/}#ifnd
ef__OpenBSD__/**SetMD5keyforthesocket,forthegivenpeeraddress.Ifthepassword*isNUL
Lorzero-length,theoptionwillbedisabled.*/intsock_set_md5sig(intfd,intaf,unionldp
d_addr*addr,constchar*password){intret=-1;intsave_errno=ENOSYS;#ifHAVE_DECL_TCP_
MD5SIGunionsockunionsu;#endifif(fd==-1)return(0);#ifHAVE_DECL_TCP_MD5SIGmemcpy(&
su,addr2sa(af,addr,0),sizeof(su));if(ldpe_privs.change(ZPRIVS_RAISE)){log_warn("
%s:couldnotraiseprivs",__func__);return(-1);}ret=sockopt_tcp_signature(fd,&su,pa
ssword);save_errno=errno;if(ldpe_privs.change(ZPRIVS_LOWER))log_warn("%s:couldno
tlowerprivs",__func__);#endif/*HAVE_TCP_MD5SIG*/if(ret<0)log_warnx("%s:can'tsetT
CP_MD5SIGoptiononfd%d:%s",__func__,fd,safe_strerror(save_errno));return(ret);}#e
ndifintsock_set_ipv4_tos(intfd,inttos){if(setsockopt(fd,IPPROTO_IP,IP_TOS,(int*)
&tos,sizeof(tos))<0){log_warn("%s:errorsettingIP_TOSto0x%x",__func__,tos);return
(-1);}return(0);}intsock_set_ipv4_recvif(intfd,intenable){return(setsockopt_ifin
dex(AF_INET,fd,enable));}intsock_set_ipv4_minttl(intfd,intttl){return(sockopt_mi
nttl(AF_INET,fd,ttl));}intsock_set_ipv4_ucast_ttl(intfd,intttl){if(setsockopt(fd
,IPPROTO_IP,IP_TTL,&ttl,sizeof(ttl))<0){log_warn("%s:errorsettingIP_TTL",__func_
_);return(-1);}return(0);}intsock_set_ipv4_mcast_ttl(intfd,uint8_tttl){if(setsoc
kopt(fd,IPPROTO_IP,IP_MULTICAST_TTL,(char*)&ttl,sizeof(ttl))<0){log_warn("%s:err
orsettingIP_MULTICAST_TTLto%d",__func__,ttl);return(-1);}return(0);}#ifndefMSG_M
CAST#ifdefined(HAVE_IP_PKTINFO)intsock_set_ipv4_pktinfo(intfd,intenable){if(sets
ockopt(fd,IPPROTO_IP,IP_PKTINFO,&enable,sizeof(enable))<0){log_warn("%s:errorset
tingIP_PKTINFO",__func__);return(-1);}return(0);}#elifdefined(HAVE_IP_RECVDSTADD
R)intsock_set_ipv4_recvdstaddr(intfd,intenable){if(setsockopt(fd,IPPROTO_IP,IP_R
ECVDSTADDR,&enable,sizeof(enable))<0){log_warn("%s:errorsettingIP_RECVDSTADDR",_
_func__);return(-1);}return(0);}#else#error"UnsupportedsocketAPI"#endif#endif/*M
SG_MCAST*/intsock_set_ipv4_mcast(structiface*iface){structin_addrif_addr;if_addr
.s_addr=if_get_ipv4_addr(iface);if(setsockopt_ipv4_multicast_if(global.ipv4.ldp_
disc_socket,if_addr,iface->ifindex)<0){log_warn("%s:errorsettingIP_MULTICAST_IF,
interface%s",__func__,iface->name);return(-1);}return(0);}intsock_set_ipv4_mcast
_loop(intfd){return(setsockopt_ipv4_multicast_loop(fd,0));}intsock_set_ipv6_dscp
(intfd,intdscp){if(setsockopt(fd,IPPROTO_IPV6,IPV6_TCLASS,&dscp,sizeof(dscp))<0)
{log_warn("%s:errorsettingIPV6_TCLASS",__func__);return(-1);}return(0);}intsock_
set_ipv6_pktinfo(intfd,intenable){if(setsockopt(fd,IPPROTO_IPV6,IPV6_RECVPKTINFO
,&enable,sizeof(enable))<0){log_warn("%s:errorsettingIPV6_RECVPKTINFO",__func__)
;return(-1);}return(0);}intsock_set_ipv6_minhopcount(intfd,inthoplimit){return(s
ockopt_minttl(AF_INET6,fd,hoplimit));}intsock_set_ipv6_ucast_hops(intfd,inthopli
mit){if(setsockopt(fd,IPPROTO_IPV6,IPV6_UNICAST_HOPS,&hoplimit,sizeof(hoplimit))
<0){log_warn("%s:errorsettingIPV6_UNICAST_HOPS",__func__);return(-1);}return(0);
}intsock_set_ipv6_mcast_hops(intfd,inthoplimit){if(setsockopt(fd,IPPROTO_IPV6,IP
V6_MULTICAST_HOPS,&hoplimit,sizeof(hoplimit))<0){log_warn("%s:errorsettingIPV6_M
ULTICAST_HOPS",__func__);return(-1);}return(0);}intsock_set_ipv6_mcast(structifa
ce*iface){if(setsockopt(global.ipv6.ldp_disc_socket,IPPROTO_IPV6,IPV6_MULTICAST_
IF,&iface->ifindex,sizeof(iface->ifindex))<0){log_warn("%s:errorsettingIPV6_MULT
ICAST_IF,interface%s",__func__,iface->name);return(-1);}return(0);}intsock_set_i
pv6_mcast_loop(intfd){unsignedintloop=0;if(setsockopt(fd,IPPROTO_IPV6,IPV6_MULTI
CAST_LOOP,&loop,sizeof(loop))<0){log_warn("%s:errorsettingIPV6_MULTICAST_LOOP",_
_func__);return(-1);}return(0);}