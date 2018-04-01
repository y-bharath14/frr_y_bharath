/*Threadmanagementroutine*Copyright(C)1998,2000KunihiroIshiguro<kunihiro@zebra.o
rg>**ThisfileispartofGNUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/o
rmodifyit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftware
Foundation;eitherversion2,or(atyouroption)any*laterversion.**GNUZebraisdistribut
edinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarran
tyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicens
eformoredetails.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*wi
ththisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51F
ranklinSt,FifthFloor,Boston,MA02110-1301USA*//*#defineDEBUG*/#include<zebra.h>#i
nclude<sys/resource.h>#include"thread.h"#include"memory.h"#include"log.h"#includ
e"hash.h"#include"pqueue.h"#include"command.h"#include"sigevent.h"#include"netwo
rk.h"#include"jhash.h"DEFINE_MTYPE_STATIC(LIB,THREAD,"Thread")DEFINE_MTYPE_STATI
C(LIB,THREAD_MASTER,"Threadmaster")DEFINE_MTYPE_STATIC(LIB,THREAD_STATS,"Threads
tats")#ifdefined(__APPLE__)#include<mach/mach.h>#include<mach/mach_time.h>#endif
#defineAWAKEN(m)\do{\staticunsignedcharwakebyte=0x01;\write(m->io_pipe[1],&wakeb
yte,1);\}while(0);/*controlvariableforinitializer*/pthread_once_tinit_once=PTHRE
AD_ONCE_INIT;pthread_key_tthread_current;pthread_mutex_tmasters_mtx=PTHREAD_MUTE
X_INITIALIZER;staticstructlist*masters;/*CLIstart-------------------------------
---------------------------------*/staticunsignedintcpu_record_hash_key(structcp
u_thread_history*a){intsize=sizeof(&a->func);returnjhash(&a->func,size,0);}stati
cintcpu_record_hash_cmp(conststructcpu_thread_history*a,conststructcpu_thread_hi
story*b){returna->func==b->func;}staticvoid*cpu_record_hash_alloc(structcpu_thre
ad_history*a){structcpu_thread_history*new;new=XCALLOC(MTYPE_THREAD_STATS,sizeof
(structcpu_thread_history));new->func=a->func;new->funcname=a->funcname;returnne
w;}staticvoidcpu_record_hash_free(void*a){structcpu_thread_history*hist=a;XFREE(
MTYPE_THREAD_STATS,hist);}staticvoidvty_out_cpu_thread_history(structvty*vty,str
uctcpu_thread_history*a){vty_out(vty,"%5d%10lu.%03lu%9u%8lu%9lu%8lu%9lu",a->tota
l_active,a->cpu.total/1000,a->cpu.total%1000,a->total_calls,a->cpu.total/a->tota
l_calls,a->cpu.max,a->real.total/a->total_calls,a->real.max);vty_out(vty,"%c%c%c
%c%c%s\n",a->types&(1<<THREAD_READ)?'R':'',a->types&(1<<THREAD_WRITE)?'W':'',a->
types&(1<<THREAD_TIMER)?'T':'',a->types&(1<<THREAD_EVENT)?'E':'',a->types&(1<<TH
READ_EXECUTE)?'X':'',a->funcname);}staticvoidcpu_record_hash_print(structhash_ba
cket*bucket,void*args[]){structcpu_thread_history*totals=args[0];structvty*vty=a
rgs[1];thread_type*filter=args[2];structcpu_thread_history*a=bucket->data;if(!(a
->types&*filter))return;vty_out_cpu_thread_history(vty,a);totals->total_active+=
a->total_active;totals->total_calls+=a->total_calls;totals->real.total+=a->real.
total;if(totals->real.max<a->real.max)totals->real.max=a->real.max;totals->cpu.t
otal+=a->cpu.total;if(totals->cpu.max<a->cpu.max)totals->cpu.max=a->cpu.max;}sta
ticvoidcpu_record_print(structvty*vty,thread_typefilter){structcpu_thread_histor
ytmp;void*args[3]={&tmp,vty,&filter};structthread_master*m;structlistnode*ln;mem
set(&tmp,0,sizeoftmp);tmp.funcname="TOTAL";tmp.types=filter;pthread_mutex_lock(&
masters_mtx);{for(ALL_LIST_ELEMENTS_RO(masters,ln,m)){constchar*name=m->name?m->
name:"main";charunderline[strlen(name)+1];memset(underline,'-',sizeof(underline)
);underline[sizeof(underline)]='\0';vty_out(vty,"\n");vty_out(vty,"Showingstatis
ticsforpthread%s\n",name);vty_out(vty,"-------------------------------%s\n",unde
rline);vty_out(vty,"%21s%18s%18s\n","","CPU(user+system):","Real(wall-clock):");
vty_out(vty,"ActiveRuntime(ms)InvokedAvguSecMaxuSecs");vty_out(vty,"AvguSecMaxuS
ecs");vty_out(vty,"TypeThread\n");if(m->cpu_record->count)hash_iterate(m->cpu_re
cord,(void(*)(structhash_backet*,void*))cpu_record_hash_print,args);elsevty_out(
vty,"Nodatatodisplayyet.\n");vty_out(vty,"\n");}}pthread_mutex_unlock(&masters_m
tx);vty_out(vty,"\n");vty_out(vty,"Totalthreadstatistics\n");vty_out(vty,"------
-------------------\n");vty_out(vty,"%21s%18s%18s\n","","CPU(user+system):","Rea
l(wall-clock):");vty_out(vty,"ActiveRuntime(ms)InvokedAvguSecMaxuSecs");vty_out(
vty,"AvguSecMaxuSecs");vty_out(vty,"TypeThread\n");if(tmp.total_calls>0)vty_out_
cpu_thread_history(vty,&tmp);}staticvoidcpu_record_hash_clear(structhash_backet*
bucket,void*args[]){thread_type*filter=args[0];structhash*cpu_record=args[1];str
uctcpu_thread_history*a=bucket->data;if(!(a->types&*filter))return;hash_release(
cpu_record,bucket->data);}staticvoidcpu_record_clear(thread_typefilter){thread_t
ype*tmp=&filter;structthread_master*m;structlistnode*ln;pthread_mutex_lock(&mast
ers_mtx);{for(ALL_LIST_ELEMENTS_RO(masters,ln,m)){pthread_mutex_lock(&m->mtx);{v
oid*args[2]={tmp,m->cpu_record};hash_iterate(m->cpu_record,(void(*)(structhash_b
acket*,void*))cpu_record_hash_clear,args);}pthread_mutex_unlock(&m->mtx);}}pthre
ad_mutex_unlock(&masters_mtx);}staticthread_typeparse_filter(constchar*filterstr
){inti=0;intfilter=0;while(filterstr[i]!='\0'){switch(filterstr[i]){case'r':case
'R':filter|=(1<<THREAD_READ);break;case'w':case'W':filter|=(1<<THREAD_WRITE);bre
ak;case't':case'T':filter|=(1<<THREAD_TIMER);break;case'e':case'E':filter|=(1<<T
HREAD_EVENT);break;case'x':case'X':filter|=(1<<THREAD_EXECUTE);break;default:bre
ak;}++i;}returnfilter;}DEFUN(show_thread_cpu,show_thread_cpu_cmd,"showthreadcpu[
FILTER]",SHOW_STR"Threadinformation\n""ThreadCPUusage\n""Displayfilter(rwtexb)\n
"){thread_typefilter=(thread_type)-1U;intidx=0;if(argv_find(argv,argc,"FILTER",&
idx)){filter=parse_filter(argv[idx]->arg);if(!filter){vty_out(vty,"Invalidfilter
\"%s\"specified;mustcontainatleast""oneof'RWTEXB'\n",argv[idx]->arg);returnCMD_W
ARNING;}}cpu_record_print(vty,filter);returnCMD_SUCCESS;}DEFUN(clear_thread_cpu,
clear_thread_cpu_cmd,"clearthreadcpu[FILTER]","Clearstoreddatainallpthreads\n""T
hreadinformation\n""ThreadCPUusage\n""Displayfilter(rwtexb)\n"){thread_typefilte
r=(thread_type)-1U;intidx=0;if(argv_find(argv,argc,"FILTER",&idx)){filter=parse_
filter(argv[idx]->arg);if(!filter){vty_out(vty,"Invalidfilter\"%s\"specified;mus
tcontainatleast""oneof'RWTEXB'\n",argv[idx]->arg);returnCMD_WARNING;}}cpu_record
_clear(filter);returnCMD_SUCCESS;}voidthread_cmd_init(void){install_element(VIEW
_NODE,&show_thread_cpu_cmd);install_element(ENABLE_NODE,&clear_thread_cpu_cmd);}
/*CLIend------------------------------------------------------------------*/stat
icintthread_timer_cmp(void*a,void*b){structthread*thread_a=a;structthread*thread
_b=b;if(timercmp(&thread_a->u.sands,&thread_b->u.sands,<))return-1;if(timercmp(&
thread_a->u.sands,&thread_b->u.sands,>))return1;return0;}staticvoidthread_timer_
update(void*node,intactual_position){structthread*thread=node;thread->index=actu
al_position;}staticvoidcancelreq_del(void*cr){XFREE(MTYPE_TMP,cr);}/*initializer
,onlyevercalledonce*/staticvoidinitializer(){pthread_key_create(&thread_current,
NULL);}structthread_master*thread_master_create(constchar*name){structthread_mas
ter*rv;structrlimitlimit;pthread_once(&init_once,&initializer);rv=XCALLOC(MTYPE_
THREAD_MASTER,sizeof(structthread_master));if(rv==NULL)returnNULL;/*Initializema
stermutex*/pthread_mutex_init(&rv->mtx,NULL);pthread_cond_init(&rv->cancel_cond,
NULL);/*Setname*/rv->name=name?XSTRDUP(MTYPE_THREAD_MASTER,name):NULL;/*Initiali
zeI/Otaskdatastructures*/getrlimit(RLIMIT_NOFILE,&limit);rv->fd_limit=(int)limit
.rlim_cur;rv->read=XCALLOC(MTYPE_THREAD,sizeof(structthread*)*rv->fd_limit);if(r
v->read==NULL){XFREE(MTYPE_THREAD_MASTER,rv);returnNULL;}rv->write=XCALLOC(MTYPE
_THREAD,sizeof(structthread*)*rv->fd_limit);if(rv->write==NULL){XFREE(MTYPE_THRE
AD,rv->read);XFREE(MTYPE_THREAD_MASTER,rv);returnNULL;}rv->cpu_record=hash_creat
e_size(8,(unsignedint(*)(void*))cpu_record_hash_key,(int(*)(constvoid*,constvoid
*))cpu_record_hash_cmp,"ThreadHash");/*Initializethetimerqueues*/rv->timer=pqueu
e_create();rv->timer->cmp=thread_timer_cmp;rv->timer->update=thread_timer_update
;/*Initializethread_fetch()settings*/rv->spin=true;rv->handle_signals=true;/*Set
pthreadowner,shouldbeupdatedbyactualowner*/rv->owner=pthread_self();rv->cancel_r
eq=list_new();rv->cancel_req->del=cancelreq_del;rv->canceled=true;/*Initializepi
pepoker*/pipe(rv->io_pipe);set_nonblocking(rv->io_pipe[0]);set_nonblocking(rv->i
o_pipe[1]);/*Initializedatastructuresforpoll()*/rv->handler.pfdsize=rv->fd_limit
;rv->handler.pfdcount=0;rv->handler.pfds=XCALLOC(MTYPE_THREAD_MASTER,sizeof(stru
ctpollfd)*rv->handler.pfdsize);rv->handler.copy=XCALLOC(MTYPE_THREAD_MASTER,size
of(structpollfd)*rv->handler.pfdsize);/*addtolistofthreadmasters*/pthread_mutex_
lock(&masters_mtx);{if(!masters)masters=list_new();listnode_add(masters,rv);}pth
read_mutex_unlock(&masters_mtx);returnrv;}voidthread_master_set_name(structthrea
d_master*master,constchar*name){pthread_mutex_lock(&master->mtx);{if(master->nam
e)XFREE(MTYPE_THREAD_MASTER,master->name);master->name=XSTRDUP(MTYPE_THREAD_MAST
ER,name);}pthread_mutex_unlock(&master->mtx);}/*Addanewthreadtothelist.*/staticv
oidthread_list_add(structthread_list*list,structthread*thread){thread->next=NULL
;thread->prev=list->tail;if(list->tail)list->tail->next=thread;elselist->head=th
read;list->tail=thread;list->count++;}/*Deleteathreadfromthelist.*/staticstructt
hread*thread_list_delete(structthread_list*list,structthread*thread){if(thread->
next)thread->next->prev=thread->prev;elselist->tail=thread->prev;if(thread->prev
)thread->prev->next=thread->next;elselist->head=thread->next;thread->next=thread
->prev=NULL;list->count--;returnthread;}/*Threadlistisemptyornot.*/staticintthre
ad_empty(structthread_list*list){returnlist->head?0:1;}/*Deletetopofthelistandre
turnit.*/staticstructthread*thread_trim_head(structthread_list*list){if(!thread_
empty(list))returnthread_list_delete(list,list->head);returnNULL;}/*Movethreadto
unuselist.*/staticvoidthread_add_unuse(structthread_master*m,structthread*thread
){assert(m!=NULL&&thread!=NULL);assert(thread->next==NULL);assert(thread->prev==
NULL);thread->ref=NULL;thread->type=THREAD_UNUSED;thread->hist->total_active--;t
hread_list_add(&m->unuse,thread);}/*Freeallunusedthread.*/staticvoidthread_list_
free(structthread_master*m,structthread_list*list){structthread*t;structthread*n
ext;for(t=list->head;t;t=next){next=t->next;XFREE(MTYPE_THREAD,t);list->count--;
m->alloc--;}}staticvoidthread_array_free(structthread_master*m,structthread**thr
ead_array){structthread*t;intindex;for(index=0;index<m->fd_limit;++index){t=thre
ad_array[index];if(t){thread_array[index]=NULL;XFREE(MTYPE_THREAD,t);m->alloc--;
}}XFREE(MTYPE_THREAD,thread_array);}staticvoidthread_queue_free(structthread_mas
ter*m,structpqueue*queue){inti;for(i=0;i<queue->size;i++)XFREE(MTYPE_THREAD,queu
e->array[i]);m->alloc-=queue->size;pqueue_delete(queue);}/**thread_master_free_u
nused**Asthreadsarefinishedwiththeyareputonthe*unuselistforlaterreuse.*Ifwearesh
uttingdown,Freeupunusedthreads*Sowecanseeifweforgettoshutanythingoff*/voidthread
_master_free_unused(structthread_master*m){pthread_mutex_lock(&m->mtx);{structth
read*t;while((t=thread_trim_head(&m->unuse))!=NULL){pthread_mutex_destroy(&t->mt
x);XFREE(MTYPE_THREAD,t);}}pthread_mutex_unlock(&m->mtx);}/*Stopthreadscheduler.
*/voidthread_master_free(structthread_master*m){pthread_mutex_lock(&masters_mtx)
;{listnode_delete(masters,m);if(masters->count==0){list_delete_and_null(&masters
);}}pthread_mutex_unlock(&masters_mtx);thread_array_free(m,m->read);thread_array
_free(m,m->write);thread_queue_free(m,m->timer);thread_list_free(m,&m->event);th
read_list_free(m,&m->ready);thread_list_free(m,&m->unuse);pthread_mutex_destroy(
&m->mtx);pthread_cond_destroy(&m->cancel_cond);close(m->io_pipe[0]);close(m->io_
pipe[1]);list_delete_and_null(&m->cancel_req);m->cancel_req=NULL;hash_clean(m->c
pu_record,cpu_record_hash_free);hash_free(m->cpu_record);m->cpu_record=NULL;if(m
->name)XFREE(MTYPE_THREAD_MASTER,m->name);XFREE(MTYPE_THREAD_MASTER,m->handler.p
fds);XFREE(MTYPE_THREAD_MASTER,m->handler.copy);XFREE(MTYPE_THREAD_MASTER,m);}/*
Returnremaintimeinsecond.*/unsignedlongthread_timer_remain_second(structthread*t
hread){int64_tremain;pthread_mutex_lock(&thread->mtx);{remain=monotime_until(&th
read->u.sands,NULL)/1000000LL;}pthread_mutex_unlock(&thread->mtx);returnremain<0
?0:remain;}#definedebugargdefconstchar*funcname,constchar*schedfrom,intfromln#de
finedebugargpassfuncname,schedfrom,fromlnstructtimevalthread_timer_remain(struct
thread*thread){structtimevalremain;pthread_mutex_lock(&thread->mtx);{monotime_un
til(&thread->u.sands,&remain);}pthread_mutex_unlock(&thread->mtx);returnremain;}
/*Getnewthread.*/staticstructthread*thread_get(structthread_master*m,uint8_ttype
,int(*func)(structthread*),void*arg,debugargdef){structthread*thread=thread_trim
_head(&m->unuse);structcpu_thread_historytmp;if(!thread){thread=XCALLOC(MTYPE_TH
READ,sizeof(structthread));/*mutexonlyneedstobeinitializedatstructcreation.*/pth
read_mutex_init(&thread->mtx,NULL);m->alloc++;}thread->type=type;thread->add_typ
e=type;thread->master=m;thread->arg=arg;thread->index=-1;thread->yield=THREAD_YI
ELD_TIME_SLOT;/*default*/thread->ref=NULL;/**Soifthepassedinfuncnameisnotwhatweh
ave*storedthatmeansthethread->histneedstobe*updated.Wekeepthelastonearoundinunus
ed*undertheassumptionthatweareprobably*goingtoimmediatelyallocatethesame*typeoft
hread.*Thishopefullysavesussomeserious*hash_getlookups.*/if(thread->funcname!=fu
ncname||thread->func!=func){tmp.func=func;tmp.funcname=funcname;thread->hist=has
h_get(m->cpu_record,&tmp,(void*(*)(void*))cpu_record_hash_alloc);}thread->hist->
total_active++;thread->func=func;thread->funcname=funcname;thread->schedfrom=sch
edfrom;thread->schedfrom_line=fromln;returnthread;}staticintfd_poll(structthread
_master*m,structpollfd*pfds,nfds_tpfdsize,nfds_tcount,conststructtimeval*timer_w
ait){/*Iftimer_waitisnullhere,thatmeanspoll()shouldblock*indefinitely,*unlessthe
thread_masterhasoverridenitbysetting*->selectpoll_timeout.*Ifthevalueispositive,
itspecifiesthemaximumnumberof*milliseconds*towait.Ifthetimeoutis-1,itspecifiesth
atweshouldneverwait*and*alwaysreturnimmediatelyevenifnoeventisdetected.Ifthevalu
e*is*zero,thebehaviorisdefault.*/inttimeout=-1;/*numberoffiledescriptorswitheven
ts*/intnum;if(timer_wait!=NULL&&m->selectpoll_timeout==0)//usethedefaultvaluetim
eout=(timer_wait->tv_sec*1000)+(timer_wait->tv_usec/1000);elseif(m->selectpoll_t
imeout>0)//usetheuser'stimeouttimeout=m->selectpoll_timeout;elseif(m->selectpoll
_timeout<0)//effectapoll(returnimmediately)timeout=0;/*addpollpipepoker*/assert(
count+1<pfdsize);pfds[count].fd=m->io_pipe[0];pfds[count].events=POLLIN;pfds[cou
nt].revents=0x00;num=poll(pfds,count+1,timeout);unsignedchartrash[64];if(num>0&&
pfds[count].revents!=0&&num--)while(read(m->io_pipe[0],&trash,sizeof(trash))>0);
returnnum;}/*Addnewreadthread.*/structthread*funcname_thread_add_read_write(intd
ir,structthread_master*m,int(*func)(structthread*),void*arg,intfd,structthread**
t_ptr,debugargdef){structthread*thread=NULL;pthread_mutex_lock(&m->mtx);{if(t_pt
r&&*t_ptr)//threadisalreadyscheduled;don'treschedule{pthread_mutex_unlock(&m->mt
x);returnNULL;}/*defaulttoanewpollfd*/nfds_tqueuepos=m->handler.pfdcount;/*ifwea
lreadyhaveapollfdforourfiledescriptor,findand*useit*/for(nfds_ti=0;i<m->handler.
pfdcount;i++)if(m->handler.pfds[i].fd==fd){queuepos=i;break;}/*makesurewehaveroo
mforthisfd+pipepokerfd*/assert(queuepos+1<m->handler.pfdsize);thread=thread_get(
m,dir,func,arg,debugargpass);m->handler.pfds[queuepos].fd=fd;m->handler.pfds[que
uepos].events|=(dir==THREAD_READ?POLLIN:POLLOUT);if(queuepos==m->handler.pfdcoun
t)m->handler.pfdcount++;if(thread){pthread_mutex_lock(&thread->mtx);{thread->u.f
d=fd;if(dir==THREAD_READ)m->read[thread->u.fd]=thread;elsem->write[thread->u.fd]
=thread;}pthread_mutex_unlock(&thread->mtx);if(t_ptr){*t_ptr=thread;thread->ref=
t_ptr;}}AWAKEN(m);}pthread_mutex_unlock(&m->mtx);returnthread;}staticstructthrea
d*funcname_thread_add_timer_timeval(structthread_master*m,int(*func)(structthrea
d*),inttype,void*arg,structtimeval*time_relative,structthread**t_ptr,debugargdef
){structthread*thread;structpqueue*queue;assert(m!=NULL);assert(type==THREAD_TIM
ER);assert(time_relative);pthread_mutex_lock(&m->mtx);{if(t_ptr&&*t_ptr)//thread
isalreadyscheduled;don'treschedule{pthread_mutex_unlock(&m->mtx);returnNULL;}que
ue=m->timer;thread=thread_get(m,type,func,arg,debugargpass);pthread_mutex_lock(&
thread->mtx);{monotime(&thread->u.sands);timeradd(&thread->u.sands,time_relative
,&thread->u.sands);pqueue_enqueue(thread,queue);if(t_ptr){*t_ptr=thread;thread->
ref=t_ptr;}}pthread_mutex_unlock(&thread->mtx);AWAKEN(m);}pthread_mutex_unlock(&
m->mtx);returnthread;}/*Addtimereventthread.*/structthread*funcname_thread_add_t
imer(structthread_master*m,int(*func)(structthread*),void*arg,longtimer,structth
read**t_ptr,debugargdef){structtimevaltrel;assert(m!=NULL);trel.tv_sec=timer;tre
l.tv_usec=0;returnfuncname_thread_add_timer_timeval(m,func,THREAD_TIMER,arg,&tre
l,t_ptr,debugargpass);}/*Addtimereventthreadwith"millisecond"resolution*/structt
hread*funcname_thread_add_timer_msec(structthread_master*m,int(*func)(structthre
ad*),void*arg,longtimer,structthread**t_ptr,debugargdef){structtimevaltrel;asser
t(m!=NULL);trel.tv_sec=timer/1000;trel.tv_usec=1000*(timer%1000);returnfuncname_
thread_add_timer_timeval(m,func,THREAD_TIMER,arg,&trel,t_ptr,debugargpass);}/*Ad
dtimereventthreadwith"millisecond"resolution*/structthread*funcname_thread_add_t
imer_tv(structthread_master*m,int(*func)(structthread*),void*arg,structtimeval*t
v,structthread**t_ptr,debugargdef){returnfuncname_thread_add_timer_timeval(m,fun
c,THREAD_TIMER,arg,tv,t_ptr,debugargpass);}/*Addsimpleeventthread.*/structthread
*funcname_thread_add_event(structthread_master*m,int(*func)(structthread*),void*
arg,intval,structthread**t_ptr,debugargdef){structthread*thread;assert(m!=NULL);
pthread_mutex_lock(&m->mtx);{if(t_ptr&&*t_ptr)//threadisalreadyscheduled;don'tre
schedule{pthread_mutex_unlock(&m->mtx);returnNULL;}thread=thread_get(m,THREAD_EV
ENT,func,arg,debugargpass);pthread_mutex_lock(&thread->mtx);{thread->u.val=val;t
hread_list_add(&m->event,thread);}pthread_mutex_unlock(&thread->mtx);if(t_ptr){*
t_ptr=thread;thread->ref=t_ptr;}AWAKEN(m);}pthread_mutex_unlock(&m->mtx);returnt
hread;}/*Threadcancellation-----------------------------------------------------
-*//***NOT'soutthe.eventsfieldofpollfdcorrespondingtothegivenfile*descriptor.The
eventtobeNOT'dispassedinthe'state'parameter.**Thisneedstohappenforbothcopiesofpo
llfd's.See'thread_fetch'*implementationfordetails.**@parammaster*@paramfd*@param
statetheeventtocancel.Oneormore(OR'dtogether)ofthe*following:*-POLLIN*-POLLOUT*/
staticvoidthread_cancel_rw(structthread_master*master,intfd,shortstate){boolfoun
d=false;/*CancelPOLLHUPtoojustincasesomebozosetit*/state|=POLLHUP;/*findtheindex
ofcorrespondingpollfd*/nfds_ti;for(i=0;i<master->handler.pfdcount;i++)if(master-
>handler.pfds[i].fd==fd){found=true;break;}if(!found){zlog_debug("[!]Receivedcan
cellationrequestfornonexistentrwjob");zlog_debug("[!]threadmaster:%s|fd:%d",mast
er->name?master->name:"",fd);return;}/*NOToutevent.*/master->handler.pfds[i].eve
nts&=~(state);/*Ifalleventsarecanceled,delete/resizethepollfdarray.*/if(master->
handler.pfds[i].events==0){memmove(master->handler.pfds+i,master->handler.pfds+i
+1,(master->handler.pfdcount-i-1)*sizeof(structpollfd));master->handler.pfdcount
--;}/*Ifwehavethesamepollfdinthecopy,performthesameoperations,*otherwisereturn.*
/if(i>=master->handler.copycount)return;master->handler.copy[i].events&=~(state)
;if(master->handler.copy[i].events==0){memmove(master->handler.copy+i,master->ha
ndler.copy+i+1,(master->handler.copycount-i-1)*sizeof(structpollfd));master->han
dler.copycount--;}}/***Processcancellationrequests.**Thismayonlyberunfromthepthr
eadwhichownsthethread_master.**@parammasterthethreadmastertoprocess*@REQUIREmast
er->mtx*/staticvoiddo_thread_cancel(structthread_master*master){structthread_lis
t*list=NULL;structpqueue*queue=NULL;structthread**thread_array=NULL;structthread
*thread;structcancel_req*cr;structlistnode*ln;for(ALL_LIST_ELEMENTS_RO(master->c
ancel_req,ln,cr)){/*Ifthisisaneventobjectcancellation,linearsearch*throughevent*
listdeletinganyeventswhichhavethespecifiedargument.*Wealso*needtocheckeverythrea
dinthereadyqueue.*/if(cr->eventobj){structthread*t;thread=master->event.head;whi
le(thread){t=thread;thread=t->next;if(t->arg==cr->eventobj){thread_list_delete(&
master->event,t);if(t->ref)*t->ref=NULL;thread_add_unuse(master,t);}}thread=mast
er->ready.head;while(thread){t=thread;thread=t->next;if(t->arg==cr->eventobj){th
read_list_delete(&master->ready,t);if(t->ref)*t->ref=NULL;thread_add_unuse(maste
r,t);}}continue;}/*Thepointervariesdependingonwhetherthecancellation*requestwas*
madeasynchronouslyornot.Ifitwas,weneedtocheck*whetherthe*threadevenexistsanymore
beforecancellingit.*/thread=(cr->thread)?cr->thread:*cr->threadref;if(!thread)co
ntinue;/*Determinetheappropriatequeuetocancelthethreadfrom*/switch(thread->type)
{caseTHREAD_READ:thread_cancel_rw(master,thread->u.fd,POLLIN);thread_array=maste
r->read;break;caseTHREAD_WRITE:thread_cancel_rw(master,thread->u.fd,POLLOUT);thr
ead_array=master->write;break;caseTHREAD_TIMER:queue=master->timer;break;caseTHR
EAD_EVENT:list=&master->event;break;caseTHREAD_READY:list=&master->ready;break;d
efault:continue;break;}if(queue){assert(thread->index>=0);assert(thread==queue->
array[thread->index]);pqueue_remove_at(thread->index,queue);}elseif(list){thread
_list_delete(list,thread);}elseif(thread_array){thread_array[thread->u.fd]=NULL;
}else{assert(!"Threadshouldbeeitherinqueueorlistorarray!");}if(thread->ref)*thre
ad->ref=NULL;thread_add_unuse(thread->master,thread);}/*Deleteandfreeallcancella
tionrequests*/list_delete_all_node(master->cancel_req);/*Wakeupanythreadswhichma
ybeblockedinthread_cancel_async()*/master->canceled=true;pthread_cond_broadcast(
&master->cancel_cond);}/***Cancelanyeventswhichhavethespecifiedargument.**MT-Uns
afe**@parammthethread_mastertocancelfrom*@paramargtheargumentpassedwhencreatingt
heevent*/voidthread_cancel_event(structthread_master*master,void*arg){assert(mas
ter->owner==pthread_self());pthread_mutex_lock(&master->mtx);{structcancel_req*c
r=XCALLOC(MTYPE_TMP,sizeof(structcancel_req));cr->eventobj=arg;listnode_add(mast
er->cancel_req,cr);do_thread_cancel(master);}pthread_mutex_unlock(&master->mtx);
}/***Cancelaspecifictask.**MT-Unsafe**@paramthreadtasktocancel*/voidthread_cance
l(structthread*thread){assert(thread->master->owner==pthread_self());pthread_mut
ex_lock(&thread->master->mtx);{structcancel_req*cr=XCALLOC(MTYPE_TMP,sizeof(stru
ctcancel_req));cr->thread=thread;listnode_add(thread->master->cancel_req,cr);do_
thread_cancel(thread->master);}pthread_mutex_unlock(&thread->master->mtx);}/***A
synchronouscancellation.**Calledwitheitherastructthread**orvoid*toaneventargumen
t,*thisfunctionpoststhecorrectcancellationrequestandblocksuntilitis*serviced.**I
fthethreadiscurrentlyrunning,executionblocksuntilitcompletes.**Thelasttwoparamet
ersaremutuallyexclusive,i.e.ifyoupassonethe*othermustbeNULL.**Whenthecancellatio
nprocedureexecutesonthetargetthread_master,the*thread*providedischeckedfornullit
y.Ifitisnull,thethreadis*assumedtonolongerexistandthecancellationrequestisano-op
.Thus*usersofthisAPImustpassaback-referencewhenschedulingtheoriginal*task.**MT-S
afe**@parammasterthethreadmasterwiththerelevantevent/task*@paramthreadpointertot
hreadtocancel*@parameventobjtheevent*/voidthread_cancel_async(structthread_maste
r*master,structthread**thread,void*eventobj){assert(!(thread&&eventobj)&&(thread
||eventobj));assert(master->owner!=pthread_self());pthread_mutex_lock(&master->m
tx);{master->canceled=false;if(thread){structcancel_req*cr=XCALLOC(MTYPE_TMP,siz
eof(structcancel_req));cr->threadref=thread;listnode_add(master->cancel_req,cr);
}elseif(eventobj){structcancel_req*cr=XCALLOC(MTYPE_TMP,sizeof(structcancel_req)
);cr->eventobj=eventobj;listnode_add(master->cancel_req,cr);}AWAKEN(master);whil
e(!master->canceled)pthread_cond_wait(&master->cancel_cond,&master->mtx);}pthrea
d_mutex_unlock(&master->mtx);}/*------------------------------------------------
-------------------------*/staticstructtimeval*thread_timer_wait(structpqueue*qu
eue,structtimeval*timer_val){if(queue->size){structthread*next_timer=queue->arra
y[0];monotime_until(&next_timer->u.sands,timer_val);returntimer_val;}returnNULL;
}staticstructthread*thread_run(structthread_master*m,structthread*thread,structt
hread*fetch){*fetch=*thread;thread_add_unuse(m,thread);returnfetch;}staticintthr
ead_process_io_helper(structthread_master*m,structthread*thread,shortstate,intpo
s){structthread**thread_array;if(!thread)return0;if(thread->type==THREAD_READ)th
read_array=m->read;elsethread_array=m->write;thread_array[thread->u.fd]=NULL;thr
ead_list_add(&m->ready,thread);thread->type=THREAD_READY;/*ifanotherpthreadsched
uledthisfiledescriptorfortheeventwe're*respondingto,noproblem;we'regettingtoitno
w*/thread->master->handler.pfds[pos].events&=~(state);return1;}/***ProcessI/Oeve
nts.**Walksthroughfiledescriptorarraylookingforthosepollfdswhose.revents*fieldha
ssomethinginteresting.Deletesanyinvalidfiledescriptors.**@parammthethreadmaster*
@paramnumthenumberofactivefiledescriptors(returnvalueofpoll())*/staticvoidthread
_process_io(structthread_master*m,unsignedintnum){unsignedintready=0;structpollf
d*pfds=m->handler.copy;for(nfds_ti=0;i<m->handler.copycount&&ready<num;++i){/*no
eventforcurrentfd?immediatelycontinue*/if(pfds[i].revents==0)continue;ready++;/*
Unlesssomeonehascalledthread_cancelfromanotherpthread,*theonly*thingthatcouldhav
echangedinm->handler.pfdswhilewe*were*asleepisthe.eventsfieldinagivenpollfd.Barr
ing*thread_cancel()*thatvalueshouldbeasupersetofthevalueswehaveinour*copy,so*the
re'snoneedtoupdateit.Similarily,barringdeletion,*thefd*shouldstillbeavalidindexi
ntothemaster'spfds.*/if(pfds[i].revents&(POLLIN|POLLHUP))thread_process_io_helpe
r(m,m->read[pfds[i].fd],POLLIN,i);if(pfds[i].revents&POLLOUT)thread_process_io_h
elper(m,m->write[pfds[i].fd],POLLOUT,i);/*ifoneofourfiledescriptorsisgarbage,rem
ovethesame*from*bothpfds+updatesizesandindex*/if(pfds[i].revents&POLLNVAL){memmo
ve(m->handler.pfds+i,m->handler.pfds+i+1,(m->handler.pfdcount-i-1)*sizeof(struct
pollfd));m->handler.pfdcount--;memmove(pfds+i,pfds+i+1,(m->handler.copycount-i-1
)*sizeof(structpollfd));m->handler.copycount--;i--;}}}/*Addalltimersthathavepopp
edtothereadylist.*/staticunsignedintthread_process_timers(structpqueue*queue,str
ucttimeval*timenow){structthread*thread;unsignedintready=0;while(queue->size){th
read=queue->array[0];if(timercmp(timenow,&thread->u.sands,<))returnready;pqueue_
dequeue(queue);thread->type=THREAD_READY;thread_list_add(&thread->master->ready,
thread);ready++;}returnready;}/*processalistenmasse,e.g.foreventthreadlists*/sta
ticunsignedintthread_process(structthread_list*list){structthread*thread;structt
hread*next;unsignedintready=0;for(thread=list->head;thread;thread=next){next=thr
ead->next;thread_list_delete(list,thread);thread->type=THREAD_READY;thread_list_
add(&thread->master->ready,thread);ready++;}returnready;}/*Fetchnextreadythread.
*/structthread*thread_fetch(structthread_master*m,structthread*fetch){structthre
ad*thread=NULL;structtimevalnow;structtimevalzerotime={0,0};structtimevaltv;stru
cttimeval*tw=NULL;intnum=0;do{/*Handlesignalsifany*/if(m->handle_signals)quagga_
sigevent_process();pthread_mutex_lock(&m->mtx);/*Processanypendingcancellationre
quests*/do_thread_cancel(m);/**Attempttoflushreadyqueuebeforegoingintopoll().*Th
isisperformance-critical.Thinktwicebeforemodifying.*/if((thread=thread_trim_head
(&m->ready))){fetch=thread_run(m,thread,fetch);if(fetch->ref)*fetch->ref=NULL;pt
hread_mutex_unlock(&m->mtx);break;}/*otherwise,tickthroughschedulingsequence*//*
*Posteventstoreadyqueue.Thismustcomebeforethe*followingblocksinceeventsshouldocc
urimmediately*/thread_process(&m->event);/**Iftherearenotasksonthereadyqueue,wew
illpoll()*untilatimerexpiresorwereceiveI/O,whichevercomes*first.Thestrategyfordo
ingthisis:**-Ifthereareeventspending,setthepoll()timeouttozero*-Iftherearenoeven
tspending,buttherearetimers*pending,setthe*timeouttothesmallestremainingtimeonan
ytimer*-Ifthereareneithertimersnoreventspending,butthere*arefile*descriptorspend
ing,blockindefinitelyinpoll()*-Ifnothingispending,it'stimefortheapplicationtodie
**Ineverycaseexceptthelast,weneedtohitpoll()atleast*onceperlooptoavoidstarvation
byevents*/if(m->ready.count==0)tw=thread_timer_wait(m->timer,&tv);if(m->ready.co
unt!=0||(tw&&!timercmp(tw,&zerotime,>)))tw=&zerotime;if(!tw&&m->handler.pfdcount
==0){/*die*/pthread_mutex_unlock(&m->mtx);fetch=NULL;break;}/**Copypollfdarray+#
activepollfdsinit.Notnecessaryto*copythearraysizeasthisisfixed.*/m->handler.copy
count=m->handler.pfdcount;memcpy(m->handler.copy,m->handler.pfds,m->handler.copy
count*sizeof(structpollfd));pthread_mutex_unlock(&m->mtx);{num=fd_poll(m,m->hand
ler.copy,m->handler.pfdsize,m->handler.copycount,tw);}pthread_mutex_lock(&m->mtx
);/*Handleanyerrorsreceivedinpoll()*/if(num<0){if(errno==EINTR){pthread_mutex_un
lock(&m->mtx);/*looparoundtosignalhandler*/continue;}/*elsedie*/zlog_warn("poll(
)error:%s",safe_strerror(errno));pthread_mutex_unlock(&m->mtx);fetch=NULL;break;
}/*Posttimerstoreadyqueue.*/monotime(&now);thread_process_timers(m->timer,&now);
/*PostI/Otoreadyqueue.*/if(num>0)thread_process_io(m,num);pthread_mutex_unlock(&
m->mtx);}while(!thread&&m->spin);returnfetch;}staticunsignedlongtimeval_elapsed(
structtimevala,structtimevalb){return(((a.tv_sec-b.tv_sec)*TIMER_SECOND_MICRO)+(
a.tv_usec-b.tv_usec));}unsignedlongthread_consumed_time(RUSAGE_T*now,RUSAGE_T*st
art,unsignedlong*cputime){/*Thisis'user+sys'time.*/*cputime=timeval_elapsed(now-
>cpu.ru_utime,start->cpu.ru_utime)+timeval_elapsed(now->cpu.ru_stime,start->cpu.
ru_stime);returntimeval_elapsed(now->real,start->real);}/*Weshouldaimtoyieldafte
ryieldmilliseconds,whichdefaultstoTHREAD_YIELD_TIME_SLOT.Note:weareusingreal(wal
lclock)timeforthiscalculation.ItcouldbearguedthatCPUtimemaymakemoresenseincertai
ncontexts.Thethingstoconsiderarewhetherthethreadmayhaveblocked(inwhichcasewallti
meincreases,butCPUtimedoesnot),orwhetherthesystemisheavilyloadedwithotherprocess
escompetingforCPUtime.Onbalance,wallclocktimeseemstomakesense.Plusithastheaddedb
enefitthatgettimeofdayshouldbefasterthancallinggetrusage.*/intthread_should_yiel
d(structthread*thread){intresult;pthread_mutex_lock(&thread->mtx);{result=monoti
me_since(&thread->real,NULL)>(int64_t)thread->yield;}pthread_mutex_unlock(&threa
d->mtx);returnresult;}voidthread_set_yield_time(structthread*thread,unsignedlong
yield_time){pthread_mutex_lock(&thread->mtx);{thread->yield=yield_time;}pthread_
mutex_unlock(&thread->mtx);}voidthread_getrusage(RUSAGE_T*r){monotime(&r->real);
getrusage(RUSAGE_SELF,&(r->cpu));}/*Wecheckthreadconsumedtime.Ifthesystemhasgetr
usage,we'llusethattogetin-depthstatsontheperformanceofthethreadinadditiontowallc
locktimestatsfromgettimeofday.*/voidthread_call(structthread*thread){unsignedlon
grealtime,cputime;RUSAGE_Tbefore,after;GETRUSAGE(&before);thread->real=before.re
al;pthread_setspecific(thread_current,thread);(*thread->func)(thread);pthread_se
tspecific(thread_current,NULL);GETRUSAGE(&after);realtime=thread_consumed_time(&
after,&before,&cputime);thread->hist->real.total+=realtime;if(thread->hist->real
.max<realtime)thread->hist->real.max=realtime;thread->hist->cpu.total+=cputime;i
f(thread->hist->cpu.max<cputime)thread->hist->cpu.max=cputime;++(thread->hist->t
otal_calls);thread->hist->types|=(1<<thread->add_type);#ifdefCONSUMED_TIME_CHECK
if(realtime>CONSUMED_TIME_CHECK){/**WehaveaCPUHogonourhands.*Whingeaboutitnow,so
we'reawarethisisyetanothertask*tofix.*/zlog_warn("SLOWTHREAD:task%s(%lx)ranfor%l
ums(cputime%lums)",thread->funcname,(unsignedlong)thread->func,realtime/1000,cpu
time/1000);}#endif/*CONSUMED_TIME_CHECK*/}/*Executethread*/voidfuncname_thread_e
xecute(structthread_master*m,int(*func)(structthread*),void*arg,intval,debugargd
ef){structcpu_thread_historytmp;structthreaddummy;memset(&dummy,0,sizeof(structt
hread));pthread_mutex_init(&dummy.mtx,NULL);dummy.type=THREAD_EVENT;dummy.add_ty
pe=THREAD_EXECUTE;dummy.master=NULL;dummy.arg=arg;dummy.u.val=val;tmp.func=dummy
.func=func;tmp.funcname=dummy.funcname=funcname;dummy.hist=hash_get(m->cpu_recor
d,&tmp,(void*(*)(void*))cpu_record_hash_alloc);dummy.schedfrom=schedfrom;dummy.s
chedfrom_line=fromln;thread_call(&dummy);}