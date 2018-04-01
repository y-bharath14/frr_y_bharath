/*$OpenBSD$*//**Copyright(c)2003,2004HenningBrauer<henning@openbsd.org>**Permiss
iontouse,copy,modify,anddistributethissoftwareforany*purposewithorwithoutfeeishe
rebygranted,providedthattheabove*copyrightnoticeandthispermissionnoticeappearina
llcopies.**THESOFTWAREISPROVIDED"ASIS"ANDTHEAUTHORDISCLAIMSALLWARRANTIES*WITHREG
ARDTOTHISSOFTWAREINCLUDINGALLIMPLIEDWARRANTIESOF*MERCHANTABILITYANDFITNESS.INNOE
VENTSHALLTHEAUTHORBELIABLEFOR*ANYSPECIAL,DIRECT,INDIRECT,ORCONSEQUENTIALDAMAGESO
RANYDAMAGES*WHATSOEVERRESULTINGFROMLOSSOFUSE,DATAORPROFITS,WHETHERINAN*ACTIONOFC
ONTRACT,NEGLIGENCEOROTHERTORTIOUSACTION,ARISINGOUTOF*ORINCONNECTIONWITHTHEUSEORP
ERFORMANCEOFTHISSOFTWARE.*/#include<zebra.h>#include<sys/un.h>#include"ldpd.h"#i
nclude"ldpe.h"#include"log.h"#include"control.h"#defineCONTROL_BACKLOG5staticint
control_accept(structthread*);staticstructctl_conn*control_connbyfd(int);statics
tructctl_conn*control_connbypid(pid_t);staticvoidcontrol_close(int);staticintcon
trol_dispatch_imsg(structthread*);structctl_connsctl_conns;staticintcontrol_fd;i
ntcontrol_init(char*path){structsockaddr_uns_un;intfd;mode_told_umask;if((fd=soc
ket(AF_UNIX,SOCK_STREAM,0))==-1){log_warn("%s:socket",__func__);return(-1);}sock
_set_nonblock(fd);memset(&s_un,0,sizeof(s_un));s_un.sun_family=AF_UNIX;strlcpy(s
_un.sun_path,path,sizeof(s_un.sun_path));if(unlink(path)==-1)if(errno!=ENOENT){l
og_warn("%s:unlink%s",__func__,path);close(fd);return(-1);}old_umask=umask(S_IXU
SR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);if(bind(fd,(structsockaddr*)&s_un,sizeof(s_u
n))==-1){log_warn("%s:bind:%s",__func__,path);close(fd);umask(old_umask);return(
-1);}umask(old_umask);if(chmod(path,S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)==-1){log_wa
rn("%s:chmod",__func__);close(fd);(void)unlink(path);return(-1);}control_fd=fd;r
eturn(0);}intcontrol_listen(void){if(listen(control_fd,CONTROL_BACKLOG)==-1){log
_warn("%s:listen",__func__);return(-1);}return(accept_add(control_fd,control_acc
ept,NULL));}voidcontrol_cleanup(char*path){accept_del(control_fd);close(control_
fd);unlink(path);}/*ARGSUSED*/staticintcontrol_accept(structthread*thread){intco
nnfd;socklen_tlen;structsockaddr_uns_un;structctl_conn*c;len=sizeof(s_un);if((co
nnfd=accept(THREAD_FD(thread),(structsockaddr*)&s_un,&len))==-1){/**Pauseaccepti
fweareoutoffiledescriptors,or*libeventwillhauntusheretoo.*/if(errno==ENFILE||err
no==EMFILE)accept_pause();elseif(errno!=EWOULDBLOCK&&errno!=EINTR&&errno!=ECONNA
BORTED)log_warn("%s:accept",__func__);return(0);}sock_set_nonblock(connfd);if((c
=calloc(1,sizeof(structctl_conn)))==NULL){log_warn(__func__);close(connfd);retur
n(0);}imsg_init(&c->iev.ibuf,connfd);c->iev.handler_read=control_dispatch_imsg;c
->iev.ev_read=NULL;thread_add_read(master,c->iev.handler_read,&c->iev,c->iev.ibu
f.fd,&c->iev.ev_read);c->iev.handler_write=ldp_write_handler;c->iev.ev_write=NUL
L;TAILQ_INSERT_TAIL(&ctl_conns,c,entry);return(0);}staticstructctl_conn*control_
connbyfd(intfd){structctl_conn*c;TAILQ_FOREACH(c,&ctl_conns,entry){if(c->iev.ibu
f.fd==fd)break;}return(c);}staticstructctl_conn*control_connbypid(pid_tpid){stru
ctctl_conn*c;TAILQ_FOREACH(c,&ctl_conns,entry){if(c->iev.ibuf.pid==pid)break;}re
turn(c);}staticvoidcontrol_close(intfd){structctl_conn*c;if((c=control_connbyfd(
fd))==NULL){log_warnx("%s:fd%d:notfound",__func__,fd);return;}msgbuf_clear(&c->i
ev.ibuf.w);TAILQ_REMOVE(&ctl_conns,c,entry);THREAD_READ_OFF(c->iev.ev_read);THRE
AD_WRITE_OFF(c->iev.ev_write);close(c->iev.ibuf.fd);accept_unpause();free(c);}/*
ARGSUSED*/staticintcontrol_dispatch_imsg(structthread*thread){intfd=THREAD_FD(th
read);structctl_conn*c;structimsgimsg;ssize_tn;unsignedintifidx;if((c=control_co
nnbyfd(fd))==NULL){log_warnx("%s:fd%d:notfound",__func__,fd);return(0);}c->iev.e
v_read=NULL;if(((n=imsg_read(&c->iev.ibuf))==-1&&errno!=EAGAIN)||n==0){control_c
lose(fd);return(0);}for(;;){if((n=imsg_get(&c->iev.ibuf,&imsg))==-1){control_clo
se(fd);return(0);}if(n==0)break;switch(imsg.hdr.type){caseIMSG_CTL_FIB_COUPLE:ca
seIMSG_CTL_FIB_DECOUPLE:caseIMSG_CTL_RELOAD:caseIMSG_CTL_KROUTE:caseIMSG_CTL_KRO
UTE_ADDR:caseIMSG_CTL_IFINFO:/*ignore*/break;caseIMSG_CTL_SHOW_INTERFACE:if(imsg
.hdr.len==IMSG_HEADER_SIZE+sizeof(ifidx)){memcpy(&ifidx,imsg.data,sizeof(ifidx))
;ldpe_iface_ctl(c,ifidx);imsg_compose_event(&c->iev,IMSG_CTL_END,0,0,-1,NULL,0);
}break;caseIMSG_CTL_SHOW_DISCOVERY:ldpe_adj_ctl(c);break;caseIMSG_CTL_SHOW_DISCO
VERY_DTL:ldpe_adj_detail_ctl(c);break;caseIMSG_CTL_SHOW_LIB:caseIMSG_CTL_SHOW_L2
VPN_PW:caseIMSG_CTL_SHOW_L2VPN_BINDING:c->iev.ibuf.pid=imsg.hdr.pid;ldpe_imsg_co
mpose_lde(imsg.hdr.type,0,imsg.hdr.pid,imsg.data,imsg.hdr.len-IMSG_HEADER_SIZE);
break;caseIMSG_CTL_SHOW_NBR:ldpe_nbr_ctl(c);break;caseIMSG_CTL_CLEAR_NBR:if(imsg
.hdr.len!=IMSG_HEADER_SIZE+sizeof(structctl_nbr))break;nbr_clear_ctl(imsg.data);
break;caseIMSG_CTL_LOG_VERBOSE:/*ignore*/break;default:log_debug("%s:errorhandli
ngimsg%d",__func__,imsg.hdr.type);break;}imsg_free(&imsg);}imsg_event_add(&c->ie
v);return(0);}intcontrol_imsg_relay(structimsg*imsg){structctl_conn*c;if((c=cont
rol_connbypid(imsg->hdr.pid))==NULL)return(0);return(imsg_compose_event(&c->iev,
imsg->hdr.type,0,imsg->hdr.pid,-1,imsg->data,imsg->hdr.len-IMSG_HEADER_SIZE));}