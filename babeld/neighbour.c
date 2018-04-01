/*Copyright(c)2007,2008byJuliuszChroboczekPermissionisherebygranted,freeofcharge
,toanypersonobtainingacopyofthissoftwareandassociateddocumentationfiles(the"Soft
ware"),todealintheSoftwarewithoutrestriction,includingwithoutlimitationtherights
touse,copy,modify,merge,publish,distribute,sublicense,and/orsellcopiesoftheSoftw
are,andtopermitpersonstowhomtheSoftwareisfurnishedtodoso,subjecttothefollowingco
nditions:Theabovecopyrightnoticeandthispermissionnoticeshallbeincludedinallcopie
sorsubstantialportionsoftheSoftware.THESOFTWAREISPROVIDED"ASIS",WITHOUTWARRANTYO
FANYKIND,EXPRESSORIMPLIED,INCLUDINGBUTNOTLIMITEDTOTHEWARRANTIESOFMERCHANTABILITY
,FITNESSFORAPARTICULARPURPOSEANDNONINFRINGEMENT.INNOEVENTSHALLTHEAUTHORSORCOPYRI
GHTHOLDERSBELIABLEFORANYCLAIM,DAMAGESOROTHERLIABILITY,WHETHERINANACTIONOFCONTRAC
T,TORTOROTHERWISE,ARISINGFROM,OUTOFORINCONNECTIONWITHTHESOFTWAREORTHEUSEOROTHERD
EALINGSINTHESOFTWARE.*/#include<stdlib.h>#include<string.h>#include<stdio.h>#inc
lude<sys/time.h>#include<time.h>#include<zebra.h>#include"if.h"#include"babel_ma
in.h"#include"babeld.h"#include"util.h"#include"babel_interface.h"#include"neigh
bour.h"#include"source.h"#include"route.h"#include"message.h"#include"resend.h"s
tructneighbour*neighs=NULL;staticstructneighbour*find_neighbour_nocreate(constun
signedchar*address,structinterface*ifp){structneighbour*neigh;FOR_ALL_NEIGHBOURS
(neigh){if(memcmp(address,neigh->address,16)==0&&neigh->ifp==ifp)returnneigh;}re
turnNULL;}voidflush_neighbour(structneighbour*neigh){debugf(BABEL_DEBUG_COMMON,"
Flushingneighbour%s(reach0x%04x)",format_address(neigh->address),neigh->reach);f
lush_neighbour_routes(neigh);if(unicast_neighbour==neigh)flush_unicast(1);flush_
resends(neigh);if(neighs==neigh){neighs=neigh->next;}else{structneighbour*previo
us=neighs;while(previous->next!=neigh)previous=previous->next;previous->next=nei
gh->next;}free(neigh);}structneighbour*find_neighbour(constunsignedchar*address,
structinterface*ifp){structneighbour*neigh;conststructtimevalzero={0,0};neigh=fi
nd_neighbour_nocreate(address,ifp);if(neigh)returnneigh;debugf(BABEL_DEBUG_COMMO
N,"Creatingneighbour%son%s.",format_address(address),ifp->name);neigh=malloc(siz
eof(structneighbour));if(neigh==NULL){zlog_err("malloc(neighbour):%s",safe_strer
ror(errno));returnNULL;}neigh->hello_seqno=-1;memcpy(neigh->address,address,16);
neigh->reach=0;neigh->txcost=INFINITY;neigh->ihu_time=babel_now;neigh->hello_tim
e=zero;neigh->hello_interval=0;neigh->ihu_interval=0;neigh->hello_send_us=0;neig
h->hello_rtt_receive_time=zero;neigh->rtt=0;neigh->rtt_time=zero;neigh->ifp=ifp;
neigh->next=neighs;neighs=neigh;send_hello(ifp);returnneigh;}/*Recomputeaneighbo
ur'srxcost.Returntrueifanythingchanged.*/intupdate_neighbour(structneighbour*nei
gh,inthello,inthello_interval){intmissed_hellos;intrc=0;if(hello<0){if(neigh->he
llo_interval<=0)returnrc;missed_hellos=((int)timeval_minus_msec(&babel_now,&neig
h->hello_time)-neigh->hello_interval*7)/(neigh->hello_interval*10);if(missed_hel
los<=0)returnrc;timeval_add_msec(&neigh->hello_time,&neigh->hello_time,missed_he
llos*neigh->hello_interval*10);}else{if(neigh->hello_seqno>=0&&neigh->reach>0){m
issed_hellos=seqno_minus(hello,neigh->hello_seqno)-1;if(missed_hellos<-8){/*Prob
ablyaneighbourthatrebootedandlostitsseqno.Reboottheuniverse.*/neigh->reach=0;mis
sed_hellos=0;rc=1;}elseif(missed_hellos<0){if(hello_interval>neigh->hello_interv
al){/*Thisneighbourhasincreaseditshellointerval,andwedidn'tnotice.*/neigh->reach
<<=-missed_hellos;missed_hellos=0;}else{/*Latehello.Probablyduetothelinklayerbuf
feringpacketsduringalinkoutage.Ignoreit,butresettheexpectedseqno.*/neigh->hello_
seqno=hello;hello=-1;missed_hellos=0;}rc=1;}}else{missed_hellos=0;}neigh->hello_
time=babel_now;neigh->hello_interval=hello_interval;}if(missed_hellos>0){neigh->
reach>>=missed_hellos;neigh->hello_seqno=seqno_plus(neigh->hello_seqno,missed_he
llos);rc=1;}if(hello>=0){neigh->hello_seqno=hello;neigh->reach>>=1;neigh->reach|
=0x8000;if((neigh->reach&0xFC00)!=0xFC00)rc=1;}/*Makesuretogiveneighbourssomefee
dbackearlyafterassociation*/if((neigh->reach&0xBF00)==0x8000){/*Anewneighbour*/s
end_hello(neigh->ifp);}else{/*Don'tsendhellos,inordertoavoidapositivefeedbackloo
p.*/inta=(neigh->reach&0xC000);intb=(neigh->reach&0x3000);if((a==0xC000&&b==0)||
(a==0&&b==0x3000)){/*Reachabilityiseither1100or0011*/send_self_update(neigh->ifp
);}}if((neigh->reach&0xFC00)==0xC000){/*Thisisanewishneighbour,let'srequestafull
routedump.Weoughttoavoidthiswhenthenetworkisdense*/send_unicast_request(neigh,NU
LL,0);send_ihu(neigh,NULL);}returnrc;}staticintreset_txcost(structneighbour*neig
h){unsigneddelay;delay=timeval_minus_msec(&babel_now,&neigh->ihu_time);if(neigh-
>ihu_interval>0&&delay<neigh->ihu_interval*10U*3U)return0;/*Ifwe'relosingalotofp
ackets,weprobablylostanIHUtoo*/if(delay>=180000||(neigh->reach&0xFFF0)==0||(neig
h->ihu_interval>0&&delay>=neigh->ihu_interval*10U*10U)){neigh->txcost=INFINITY;n
eigh->ihu_time=babel_now;return1;}return0;}unsignedneighbour_txcost(structneighb
our*neigh){returnneigh->txcost;}unsignedcheck_neighbours(){structneighbour*neigh
;intchanged,rc;unsignedmsecs=50000;debugf(BABEL_DEBUG_COMMON,"Checkingneighbours
.");neigh=neighs;while(neigh){changed=update_neighbour(neigh,-1,0);if(neigh->rea
ch==0||neigh->hello_time.tv_sec>babel_now.tv_sec||/*clockstepped*/timeval_minus_
msec(&babel_now,&neigh->hello_time)>300000){structneighbour*old=neigh;neigh=neig
h->next;flush_neighbour(old);continue;}rc=reset_txcost(neigh);changed=changed||r
c;update_neighbour_metric(neigh,changed);if(neigh->hello_interval>0)msecs=MIN(ms
ecs,neigh->hello_interval*10U);if(neigh->ihu_interval>0)msecs=MIN(msecs,neigh->i
hu_interval*10U);neigh=neigh->next;}returnmsecs;}unsignedneighbour_rxcost(struct
neighbour*neigh){unsigneddelay;unsignedshortreach=neigh->reach;delay=timeval_min
us_msec(&babel_now,&neigh->hello_time);if((reach&0xFFF0)==0||delay>=180000){retu
rnINFINITY;}elseif(babel_get_if_nfo(neigh->ifp)->flags&BABEL_IF_LQ){intsreach=((
reach&0x8000)>>2)+((reach&0x4000)>>1)+(reach&0x3FFF);/*0<=sreach<=0x7FFF*/intcos
t=(0x8000*babel_get_if_nfo(neigh->ifp)->cost)/(sreach+1);/*cost>=interface->cost
*/if(delay>=40000)cost=(cost*(delay-20000)+10000)/20000;returnMIN(cost,INFINITY)
;}else{/*Toloseonehelloisamisfortune,tolosetwoiscarelessness.*/if((reach&0xC000)
==0xC000)returnbabel_get_if_nfo(neigh->ifp)->cost;elseif((reach&0xC000)==0)retur
nINFINITY;elseif((reach&0x2000))returnbabel_get_if_nfo(neigh->ifp)->cost;elseret
urnINFINITY;}}unsignedneighbour_rttcost(structneighbour*neigh){structinterface*i
fp=neigh->ifp;babel_interface_nfo*babel_ifp=babel_get_if_nfo(ifp);if(!babel_ifp-
>max_rtt_penalty||!valid_rtt(neigh))return0;/*Function:linearbehaviourbetweenrtt
_minandrtt_max.*/if(neigh->rtt<=babel_ifp->rtt_min){return0;}elseif(neigh->rtt<=
babel_ifp->rtt_max){unsignedlonglongtmp=(unsignedlonglong)babel_ifp->max_rtt_pen
alty*(neigh->rtt-babel_ifp->rtt_min)/(babel_ifp->rtt_max-babel_ifp->rtt_min);ass
ert((tmp&0x7FFFFFFF)==tmp);returntmp;}else{returnbabel_ifp->max_rtt_penalty;}}un
signedneighbour_cost(structneighbour*neigh){unsigneda,b,cost;if(!if_up(neigh->if
p))returnINFINITY;a=neighbour_txcost(neigh);if(a>=INFINITY)returnINFINITY;b=neig
hbour_rxcost(neigh);if(b>=INFINITY)returnINFINITY;if(!(babel_get_if_nfo(neigh->i
fp)->flags&BABEL_IF_LQ)||(a<256&&b<256)){cost=a;}else{/*a=256/alpha,b=256/beta,w
herealphaandbetaaretheexpectedprobabilitiesofapacketgettingthroughinthedirectand
reversedirections.*/a=MAX(a,256);b=MAX(b,256);/*1/(alpha*beta),whichisjustplainE
TX.*//*Sinceaandbarecappedto16bits,overflowisimpossible.*/cost=(a*b+128)>>8;}cos
t+=neighbour_rttcost(neigh);returnMIN(cost,INFINITY);}intvalid_rtt(structneighbo
ur*neigh){return(timeval_minus_msec(&babel_now,&neigh->rtt_time)<180000)?1:0;}