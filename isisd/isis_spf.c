/**IS-ISRout(e)ingprotocol-isis_spf.c*TheSPTalgorithm**Copyright(C)2001,2002Samp
oSaaristo*TampereUniversityofTechnology*InstituteofCommunicationsEngineering*Cop
yright(C)2017ChristianFranke<chris@opensourcerouting.org>**Thisprogramisfreesoft
ware;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicens
easpublishedbytheFree*SoftwareFoundation;eitherversion2oftheLicense,or(atyouropt
ion)*anylaterversion.**Thisprogramisdistributedinthehopethatitwillbeuseful,butWI
THOUT*ANYWARRANTY;withouteventheimpliedwarrantyofMERCHANTABILITYor*FITNESSFORAPA
RTICULARPURPOSE.SeetheGNUGeneralPublicLicensefor*moredetails.**Youshouldhaverece
ivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifn
ot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110
-1301USA*/#include<zebra.h>#include"thread.h"#include"linklist.h"#include"vty.h"
#include"log.h"#include"command.h"#include"memory.h"#include"prefix.h"#include"h
ash.h"#include"if.h"#include"table.h"#include"spf_backoff.h"#include"jhash.h"#in
clude"skiplist.h"#include"isis_constants.h"#include"isis_common.h"#include"isis_
flags.h"#include"dict.h"#include"isisd.h"#include"isis_misc.h"#include"isis_adja
cency.h"#include"isis_circuit.h"#include"isis_pdu.h"#include"isis_lsp.h"#include
"isis_dynhn.h"#include"isis_spf.h"#include"isis_route.h"#include"isis_csm.h"#inc
lude"isis_mt.h"#include"isis_tlvs.h"DEFINE_MTYPE_STATIC(ISISD,ISIS_SPF_RUN,"ISIS
SPFRunInfo");enumvertextype{VTYPE_PSEUDO_IS=1,VTYPE_PSEUDO_TE_IS,VTYPE_NONPSEUDO
_IS,VTYPE_NONPSEUDO_TE_IS,VTYPE_ES,VTYPE_IPREACH_INTERNAL,VTYPE_IPREACH_EXTERNAL
,VTYPE_IPREACH_TE,VTYPE_IP6REACH_INTERNAL,VTYPE_IP6REACH_EXTERNAL};#defineVTYPE_
IS(t)((t)>=VTYPE_PSEUDO_IS&&(t)<=VTYPE_NONPSEUDO_TE_IS)#defineVTYPE_ES(t)((t)==V
TYPE_ES)#defineVTYPE_IP(t)((t)>=VTYPE_IPREACH_INTERNAL&&(t)<=VTYPE_IP6REACH_EXTE
RNAL)/**Triple<N,d(N),{Adj(N)}>*/structisis_vertex{enumvertextypetype;union{uint
8_tid[ISIS_SYS_ID_LEN+1];structprefixprefix;}N;uint32_td_N;/*d(N)Distancefromthi
sIS*/uint16_tdepth;/*Thedepthintheimaginarytree*/structlist*Adj_N;/*{Adj(N)}next
hoporneighborlist*/structlist*parents;/*listofparentsforECMP*/uint64_tinsert_cou
nter;};/*VertexQueueandassociatedfunctions*/structisis_vertex_queue{union{struct
skiplist*slist;structlist*list;}l;structhash*hash;uint64_tinsert_counter;};stati
cunsignedisis_vertex_queue_hash_key(void*vp){structisis_vertex*vertex=vp;if(VTYP
E_IP(vertex->type))returnprefix_hash_key(&vertex->N.prefix);returnjhash(vertex->
N.id,ISIS_SYS_ID_LEN+1,0x55aa5a5a);}staticintisis_vertex_queue_hash_cmp(constvoi
d*a,constvoid*b){conststructisis_vertex*va=a,*vb=b;if(va->type!=vb->type)return0
;if(VTYPE_IP(va->type))returnprefix_cmp(&va->N.prefix,&vb->N.prefix)==0;returnme
mcmp(va->N.id,vb->N.id,ISIS_SYS_ID_LEN+1)==0;}/**Comparesvertizesforsortinginthe
TENTlist.Returnstrue*ifcandidateshouldbeconsideredbeforecurrent,falseotherwise.*
/staticintisis_vertex_queue_tent_cmp(void*a,void*b){structisis_vertex*va=a;struc
tisis_vertex*vb=b;if(va->d_N<vb->d_N)return-1;if(va->d_N>vb->d_N)return1;if(va->
type<vb->type)return-1;if(va->type>vb->type)return1;if(va->insert_counter<vb->in
sert_counter)return-1;if(va->insert_counter>vb->insert_counter)return1;return0;}
staticstructskiplist*isis_vertex_queue_skiplist(void){returnskiplist_new(0,isis_
vertex_queue_tent_cmp,NULL);}staticvoidisis_vertex_queue_init(structisis_vertex_
queue*queue,constchar*name,boolordered){if(ordered){queue->insert_counter=1;queu
e->l.slist=isis_vertex_queue_skiplist();}else{queue->insert_counter=0;queue->l.l
ist=list_new();}queue->hash=hash_create(isis_vertex_queue_hash_key,isis_vertex_q
ueue_hash_cmp,name);}staticvoidisis_vertex_del(structisis_vertex*vertex);staticv
oidisis_vertex_queue_clear(structisis_vertex_queue*queue){hash_clean(queue->hash
,NULL);if(queue->insert_counter){structisis_vertex*vertex;while(0==skiplist_firs
t(queue->l.slist,NULL,(void**)&vertex)){isis_vertex_del(vertex);skiplist_delete_
first(queue->l.slist);}queue->insert_counter=1;}else{queue->l.list->del=(void(*)
(void*))isis_vertex_del;list_delete_all_node(queue->l.list);queue->l.list->del=N
ULL;}}staticvoidisis_vertex_queue_free(structisis_vertex_queue*queue){isis_verte
x_queue_clear(queue);hash_free(queue->hash);queue->hash=NULL;if(queue->insert_co
unter){skiplist_free(queue->l.slist);queue->l.slist=NULL;}elselist_delete_and_nu
ll(&queue->l.list);}staticunsignedintisis_vertex_queue_count(structisis_vertex_q
ueue*queue){returnhashcount(queue->hash);}staticvoidisis_vertex_queue_append(str
uctisis_vertex_queue*queue,structisis_vertex*vertex){assert(!queue->insert_count
er);listnode_add(queue->l.list,vertex);structisis_vertex*inserted;inserted=hash_
get(queue->hash,vertex,hash_alloc_intern);assert(inserted==vertex);}staticvoidis
is_vertex_queue_insert(structisis_vertex_queue*queue,structisis_vertex*vertex){a
ssert(queue->insert_counter);vertex->insert_counter=queue->insert_counter++;asse
rt(queue->insert_counter!=(uint64_t)-1);skiplist_insert(queue->l.slist,vertex,ve
rtex);structisis_vertex*inserted;inserted=hash_get(queue->hash,vertex,hash_alloc
_intern);assert(inserted==vertex);}staticstructisis_vertex*isis_vertex_queue_pop
(structisis_vertex_queue*queue){assert(queue->insert_counter);structisis_vertex*
rv;if(skiplist_first(queue->l.slist,NULL,(void**)&rv))returnNULL;skiplist_delete
_first(queue->l.slist);hash_release(queue->hash,rv);returnrv;}staticvoidisis_ver
tex_queue_delete(structisis_vertex_queue*queue,structisis_vertex*vertex){assert(
queue->insert_counter);skiplist_delete(queue->l.slist,vertex,vertex);hash_releas
e(queue->hash,vertex);}#defineALL_QUEUE_ELEMENTS_RO(queue,node,data)\ALL_LIST_EL
EMENTS_RO((queue)->l.list,node,data)/*Endofvertexqueuedefinitions*/structisis_sp
ftree{structisis_vertex_queuepaths;/*theSPT*/structisis_vertex_queuetents;/*TENT
*/structisis_area*area;/*backpointertoarea*/unsignedintruncount;/*numberofrunssi
nceuptime*/time_tlast_run_timestamp;/*lastruntimestampaswalltimefordisplay*/time
_tlast_run_monotime;/*lastrunasmonotimeforscheduling*/time_tlast_run_duration;/*
lastrundurationinmsec*/uint16_tmtid;intfamily;intlevel;};/**supportsthegivenaf?*
/staticboolspeaks(uint8_t*protocols,uint8_tcount,intfamily){for(uint8_ti=0;i<cou
nt;i++){if(family==AF_INET&&protocols[i]==NLPID_IP)returntrue;if(family==AF_INET
6&&protocols[i]==NLPID_IPV6)returntrue;}returnfalse;}structisis_spf_run{structis
is_area*area;intlevel;};/*7.2.7*/staticvoidremove_excess_adjs(structlist*adjs){s
tructlistnode*node,*excess=NULL;structisis_adjacency*adj,*candidate=NULL;intcomp
;for(ALL_LIST_ELEMENTS_RO(adjs,node,adj)){if(excess==NULL)excess=node;candidate=
listgetdata(excess);if(candidate->sys_type<adj->sys_type){excess=node;continue;}
if(candidate->sys_type>adj->sys_type)continue;comp=memcmp(candidate->sysid,adj->
sysid,ISIS_SYS_ID_LEN);if(comp>0){excess=node;continue;}if(comp<0)continue;if(ca
ndidate->circuit->idx>adj->circuit->idx){excess=node;continue;}if(candidate->cir
cuit->idx<adj->circuit->idx)continue;comp=memcmp(candidate->snpa,adj->snpa,ETH_A
LEN);if(comp>0){excess=node;continue;}}list_delete_node(adjs,excess);return;}sta
ticconstchar*vtype2string(enumvertextypevtype){switch(vtype){caseVTYPE_PSEUDO_IS
:return"pseudo_IS";break;caseVTYPE_PSEUDO_TE_IS:return"pseudo_TE-IS";break;caseV
TYPE_NONPSEUDO_IS:return"IS";break;caseVTYPE_NONPSEUDO_TE_IS:return"TE-IS";break
;caseVTYPE_ES:return"ES";break;caseVTYPE_IPREACH_INTERNAL:return"IPinternal";bre
ak;caseVTYPE_IPREACH_EXTERNAL:return"IPexternal";break;caseVTYPE_IPREACH_TE:retu
rn"IPTE";break;caseVTYPE_IP6REACH_INTERNAL:return"IP6internal";break;caseVTYPE_I
P6REACH_EXTERNAL:return"IP6external";break;default:return"UNKNOWN";}returnNULL;/
*Notreached*/}staticconstchar*vid2string(structisis_vertex*vertex,char*buff,ints
ize){if(VTYPE_IS(vertex->type)||VTYPE_ES(vertex->type)){returnprint_sys_hostname
(vertex->N.id);}if(VTYPE_IP(vertex->type)){prefix2str((structprefix*)&vertex->N.
prefix,buff,size);returnbuff;}return"UNKNOWN";}staticvoidisis_vertex_id_init(str
uctisis_vertex*vertex,void*id,enumvertextypevtype){vertex->type=vtype;if(VTYPE_I
S(vtype)||VTYPE_ES(vtype)){memcpy(vertex->N.id,(uint8_t*)id,ISIS_SYS_ID_LEN+1);}
elseif(VTYPE_IP(vtype)){memcpy(&vertex->N.prefix,(structprefix*)id,sizeof(struct
prefix));}else{zlog_err("WTF!");}}staticstructisis_vertex*isis_vertex_new(void*i
d,enumvertextypevtype){structisis_vertex*vertex;vertex=XCALLOC(MTYPE_ISIS_VERTEX
,sizeof(structisis_vertex));isis_vertex_id_init(vertex,id,vtype);vertex->Adj_N=l
ist_new();vertex->parents=list_new();returnvertex;}staticvoidisis_vertex_del(str
uctisis_vertex*vertex){list_delete_and_null(&vertex->Adj_N);list_delete_and_null
(&vertex->parents);memset(vertex,0,sizeof(structisis_vertex));XFREE(MTYPE_ISIS_V
ERTEX,vertex);return;}staticvoidisis_vertex_adj_del(structisis_vertex*vertex,str
uctisis_adjacency*adj){structlistnode*node,*nextnode;if(!vertex)return;for(node=
listhead(vertex->Adj_N);node;node=nextnode){nextnode=listnextnode(node);if(listg
etdata(node)==adj)list_delete_node(vertex->Adj_N,node);}return;}structisis_spftr
ee*isis_spftree_new(structisis_area*area){structisis_spftree*tree;tree=XCALLOC(M
TYPE_ISIS_SPFTREE,sizeof(structisis_spftree));if(tree==NULL){zlog_err("ISIS-Spf:
isis_spftree_newOutofmemory!");returnNULL;}isis_vertex_queue_init(&tree->tents,"
IS-ISSPFtents",true);isis_vertex_queue_init(&tree->paths,"IS-ISSPFpaths",false);
tree->area=area;tree->last_run_timestamp=0;tree->last_run_monotime=0;tree->last_
run_duration=0;tree->runcount=0;returntree;}voidisis_spftree_del(structisis_spft
ree*spftree){isis_vertex_queue_free(&spftree->tents);isis_vertex_queue_free(&spf
tree->paths);XFREE(MTYPE_ISIS_SPFTREE,spftree);return;}staticvoidisis_spftree_ad
j_del(structisis_spftree*spftree,structisis_adjacency*adj){structlistnode*node;s
tructisis_vertex*v;if(!adj)return;assert(!isis_vertex_queue_count(&spftree->tent
s));for(ALL_QUEUE_ELEMENTS_RO(&spftree->paths,node,v))isis_vertex_adj_del(v,adj)
;return;}voidspftree_area_init(structisis_area*area){if(area->is_type&IS_LEVEL_1
){if(area->spftree[0]==NULL)area->spftree[0]=isis_spftree_new(area);if(area->spf
tree6[0]==NULL)area->spftree6[0]=isis_spftree_new(area);}if(area->is_type&IS_LEV
EL_2){if(area->spftree[1]==NULL)area->spftree[1]=isis_spftree_new(area);if(area-
>spftree6[1]==NULL)area->spftree6[1]=isis_spftree_new(area);}return;}voidspftree
_area_del(structisis_area*area){if(area->is_type&IS_LEVEL_1){if(area->spftree[0]
!=NULL){isis_spftree_del(area->spftree[0]);area->spftree[0]=NULL;}if(area->spftr
ee6[0]){isis_spftree_del(area->spftree6[0]);area->spftree6[0]=NULL;}}if(area->is
_type&IS_LEVEL_2){if(area->spftree[1]!=NULL){isis_spftree_del(area->spftree[1]);
area->spftree[1]=NULL;}if(area->spftree6[1]!=NULL){isis_spftree_del(area->spftre
e6[1]);area->spftree6[1]=NULL;}}return;}voidspftree_area_adj_del(structisis_area
*area,structisis_adjacency*adj){if(area->is_type&IS_LEVEL_1){if(area->spftree[0]
!=NULL)isis_spftree_adj_del(area->spftree[0],adj);if(area->spftree6[0]!=NULL)isi
s_spftree_adj_del(area->spftree6[0],adj);}if(area->is_type&IS_LEVEL_2){if(area->
spftree[1]!=NULL)isis_spftree_adj_del(area->spftree[1],adj);if(area->spftree6[1]
!=NULL)isis_spftree_adj_del(area->spftree6[1],adj);}return;}/**FindthesystemLSP:
returnstheLSPinourLSPdatabase*associatedwiththegivensystemID.*/staticstructisis_
lsp*isis_root_system_lsp(structisis_area*area,intlevel,uint8_t*sysid){structisis
_lsp*lsp;uint8_tlspid[ISIS_SYS_ID_LEN+2];memcpy(lspid,sysid,ISIS_SYS_ID_LEN);LSP
_PSEUDO_ID(lspid)=0;LSP_FRAGMENT(lspid)=0;lsp=lsp_search(lspid,area->lspdb[level
-1]);if(lsp&&lsp->hdr.rem_lifetime!=0)returnlsp;returnNULL;}/**AddthisIStotheroo
tofSPT*/staticstructisis_vertex*isis_spf_add_root(structisis_spftree*spftree,uin
t8_t*sysid){structisis_vertex*vertex;structisis_lsp*lsp;#ifdefEXTREME_DEBUGcharb
uff[PREFIX2STR_BUFFER];#endif/*EXTREME_DEBUG*/uint8_tid[ISIS_SYS_ID_LEN+1];memcp
y(id,sysid,ISIS_SYS_ID_LEN);LSP_PSEUDO_ID(id)=0;lsp=isis_root_system_lsp(spftree
->area,spftree->level,sysid);if(lsp==NULL)zlog_warn("ISIS-Spf:couldnotfindownl%d
LSP!",spftree->level);vertex=isis_vertex_new(id,spftree->area->oldmetric?VTYPE_N
ONPSEUDO_IS:VTYPE_NONPSEUDO_TE_IS);isis_vertex_queue_append(&spftree->paths,vert
ex);#ifdefEXTREME_DEBUGzlog_debug("ISIS-Spf:addedthisIS%s%sdepth%ddist%dtoPATHS"
,vtype2string(vertex->type),vid2string(vertex,buff,sizeof(buff)),vertex->depth,v
ertex->d_N);#endif/*EXTREME_DEBUG*/returnvertex;}staticstructisis_vertex*isis_fi
nd_vertex(structisis_vertex_queue*queue,void*id,enumvertextypevtype){structisis_
vertexquerier;isis_vertex_id_init(&querier,id,vtype);returnhash_lookup(queue->ha
sh,&querier);}/**AddavertextoTENTsortedbycostandbyvertextypeontiebreaksituation*
/staticstructisis_vertex*isis_spf_add2tent(structisis_spftree*spftree,enumvertex
typevtype,void*id,uint32_tcost,intdepth,structisis_adjacency*adj,structisis_vert
ex*parent){structisis_vertex*vertex;structlistnode*node;structisis_adjacency*par
ent_adj;#ifdefEXTREME_DEBUGcharbuff[PREFIX2STR_BUFFER];#endifassert(isis_find_ve
rtex(&spftree->paths,id,vtype)==NULL);assert(isis_find_vertex(&spftree->tents,id
,vtype)==NULL);vertex=isis_vertex_new(id,vtype);vertex->d_N=cost;vertex->depth=d
epth;if(parent){listnode_add(vertex->parents,parent);}if(parent&&parent->Adj_N&&
listcount(parent->Adj_N)>0){for(ALL_LIST_ELEMENTS_RO(parent->Adj_N,node,parent_a
dj))listnode_add(vertex->Adj_N,parent_adj);}elseif(adj){listnode_add(vertex->Adj
_N,adj);}#ifdefEXTREME_DEBUGzlog_debug("ISIS-Spf:addtoTENT%s%s%sdepth%ddist%dadj
count%d",print_sys_hostname(vertex->N.id),vtype2string(vertex->type),vid2string(
vertex,buff,sizeof(buff)),vertex->depth,vertex->d_N,listcount(vertex->Adj_N));#e
ndif/*EXTREME_DEBUG*/isis_vertex_queue_insert(&spftree->tents,vertex);returnvert
ex;}staticvoidisis_spf_add_local(structisis_spftree*spftree,enumvertextypevtype,
void*id,structisis_adjacency*adj,uint32_tcost,structisis_vertex*parent){structis
is_vertex*vertex;vertex=isis_find_vertex(&spftree->tents,id,vtype);if(vertex){/*
C.2.5c)*/if(vertex->d_N==cost){if(adj)listnode_add(vertex->Adj_N,adj);/*d)*/if(l
istcount(vertex->Adj_N)>ISIS_MAX_PATH_SPLITS)remove_excess_adjs(vertex->Adj_N);i
f(parent&&(listnode_lookup(vertex->parents,parent)==NULL))listnode_add(vertex->p
arents,parent);return;}elseif(vertex->d_N<cost){/*e)donothing*/return;}else{/*ve
rtex->d_N>cost*//*f)*/isis_vertex_queue_delete(&spftree->tents,vertex);isis_vert
ex_del(vertex);}}isis_spf_add2tent(spftree,vtype,id,cost,1,adj,parent);return;}s
taticvoidprocess_N(structisis_spftree*spftree,enumvertextypevtype,void*id,uint32
_tdist,uint16_tdepth,structisis_vertex*parent){structisis_vertex*vertex;#ifdefEX
TREME_DEBUGcharbuff[PREFIX2STR_BUFFER];#endifassert(spftree&&parent);structprefi
xp;if(vtype>=VTYPE_IPREACH_INTERNAL){prefix_copy(&p,id);apply_mask(&p);id=&p;}/*
RFC3787section5.1*/if(spftree->area->newmetric==1){if(dist>MAX_WIDE_PATH_METRIC)
return;}/*C.2.6b)*/elseif(spftree->area->oldmetric==1){if(dist>MAX_NARROW_PATH_M
ETRIC)return;}/*c)*/vertex=isis_find_vertex(&spftree->paths,id,vtype);if(vertex)
{#ifdefEXTREME_DEBUGzlog_debug("ISIS-Spf:process_N%s%s%sdist%dalreadyfoundfromPA
TH",print_sys_hostname(vertex->N.id),vtype2string(vtype),vid2string(vertex,buff,
sizeof(buff)),dist);#endif/*EXTREME_DEBUG*/assert(dist>=vertex->d_N);return;}ver
tex=isis_find_vertex(&spftree->tents,id,vtype);/*d)*/if(vertex){/*1)*/#ifdefEXTR
EME_DEBUGzlog_debug("ISIS-Spf:process_N%s%s%sdist%dparent%sadjcount%d",print_sys
_hostname(vertex->N.id),vtype2string(vtype),vid2string(vertex,buff,sizeof(buff))
,dist,(parent?print_sys_hostname(parent->N.id):"null"),(parent?listcount(parent-
>Adj_N):0));#endif/*EXTREME_DEBUG*/if(vertex->d_N==dist){structlistnode*node;str
uctisis_adjacency*parent_adj;for(ALL_LIST_ELEMENTS_RO(parent->Adj_N,node,parent_
adj))if(listnode_lookup(vertex->Adj_N,parent_adj)==NULL)listnode_add(vertex->Adj
_N,parent_adj);/*2)*/if(listcount(vertex->Adj_N)>ISIS_MAX_PATH_SPLITS)remove_exc
ess_adjs(vertex->Adj_N);if(listnode_lookup(vertex->parents,parent)==NULL)listnod
e_add(vertex->parents,parent);return;}elseif(vertex->d_N<dist){return;/*4)*/}els
e{isis_vertex_queue_delete(&spftree->tents,vertex);isis_vertex_del(vertex);}}#if
defEXTREME_DEBUGzlog_debug("ISIS-Spf:process_Nadd2tent%s%sdist%dparent%s",print_
sys_hostname(id),vtype2string(vtype),dist,(parent?print_sys_hostname(parent->N.i
d):"null"));#endif/*EXTREME_DEBUG*/isis_spf_add2tent(spftree,vtype,id,dist,depth
,NULL,parent);return;}/**C.2.6Step1*/staticintisis_spf_process_lsp(structisis_sp
ftree*spftree,structisis_lsp*lsp,uint32_tcost,uint16_tdepth,uint8_t*root_sysid,s
tructisis_vertex*parent){boolpseudo_lsp=LSP_PSEUDO_ID(lsp->hdr.lsp_id);structlis
tnode*fragnode=NULL;uint32_tdist;enumvertextypevtype;staticconstuint8_tnull_sysi
d[ISIS_SYS_ID_LEN];structisis_mt_router_info*mt_router_info=NULL;if(!lsp->tlvs)r
eturnISIS_OK;if(spftree->mtid!=ISIS_MT_IPV4_UNICAST)mt_router_info=isis_tlvs_loo
kup_mt_router_info(lsp->tlvs,spftree->mtid);if(!pseudo_lsp&&(spftree->mtid==ISIS
_MT_IPV4_UNICAST&&!speaks(lsp->tlvs->protocols_supported.protocols,lsp->tlvs->pr
otocols_supported.count,spftree->family))&&!mt_router_info)returnISIS_OK;/*RFC37
87section4SHOULDignoreoverloadbitinpseudoLSPs*/boolno_overload=(pseudo_lsp||(spf
tree->mtid==ISIS_MT_IPV4_UNICAST&&!ISIS_MASK_LSP_OL_BIT(lsp->hdr.lsp_bits))||(mt
_router_info&&!mt_router_info->overload));lspfragloop:if(lsp->hdr.seqno==0){zlog
_warn("isis_spf_process_lsp():lspwith0seq_num-ignore");returnISIS_WARNING;}#ifde
fEXTREME_DEBUGzlog_debug("ISIS-Spf:process_lsp%s",print_sys_hostname(lsp->hdr.ls
p_id));#endif/*EXTREME_DEBUG*/if(no_overload){if(pseudo_lsp||spftree->mtid==ISIS
_MT_IPV4_UNICAST){structisis_oldstyle_reach*r;for(r=(structisis_oldstyle_reach*)
lsp->tlvs->oldstyle_reach.head;r;r=r->next){/*C.2.6a)*//*Twowayconnectivity*/if(
!memcmp(r->id,root_sysid,ISIS_SYS_ID_LEN))continue;if(!pseudo_lsp&&!memcmp(r->id
,null_sysid,ISIS_SYS_ID_LEN))continue;dist=cost+r->metric;process_N(spftree,LSP_
PSEUDO_ID(r->id)?VTYPE_PSEUDO_IS:VTYPE_NONPSEUDO_IS,(void*)r->id,dist,depth+1,pa
rent);}}structisis_item_list*te_neighs=NULL;if(pseudo_lsp||spftree->mtid==ISIS_M
T_IPV4_UNICAST)te_neighs=&lsp->tlvs->extended_reach;elsete_neighs=isis_lookup_mt
_items(&lsp->tlvs->mt_reach,spftree->mtid);structisis_extended_reach*er;for(er=t
e_neighs?(structisis_extended_reach*)te_neighs->head:NULL;er;er=er->next){if(!me
mcmp(er->id,root_sysid,ISIS_SYS_ID_LEN))continue;if(!pseudo_lsp&&!memcmp(er->id,
null_sysid,ISIS_SYS_ID_LEN))continue;dist=cost+er->metric;process_N(spftree,LSP_
PSEUDO_ID(er->id)?VTYPE_PSEUDO_TE_IS:VTYPE_NONPSEUDO_TE_IS,(void*)er->id,dist,de
pth+1,parent);}}if(!pseudo_lsp&&spftree->family==AF_INET&&spftree->mtid==ISIS_MT
_IPV4_UNICAST){structisis_item_list*reachs[]={&lsp->tlvs->oldstyle_ip_reach,&lsp
->tlvs->oldstyle_ip_reach_ext};for(unsignedinti=0;i<array_size(reachs);i++){vtyp
e=i?VTYPE_IPREACH_EXTERNAL:VTYPE_IPREACH_INTERNAL;structisis_oldstyle_ip_reach*r
;for(r=(structisis_oldstyle_ip_reach*)reachs[i]->head;r;r=r->next){dist=cost+r->
metric;process_N(spftree,vtype,(void*)&r->prefix,dist,depth+1,parent);}}}if(!pse
udo_lsp&&spftree->family==AF_INET){structisis_item_list*ipv4_reachs;if(spftree->
mtid==ISIS_MT_IPV4_UNICAST)ipv4_reachs=&lsp->tlvs->extended_ip_reach;elseipv4_re
achs=isis_lookup_mt_items(&lsp->tlvs->mt_ip_reach,spftree->mtid);structisis_exte
nded_ip_reach*r;for(r=ipv4_reachs?(structisis_extended_ip_reach*)ipv4_reachs->he
ad:NULL;r;r=r->next){dist=cost+r->metric;process_N(spftree,VTYPE_IPREACH_TE,(voi
d*)&r->prefix,dist,depth+1,parent);}}if(!pseudo_lsp&&spftree->family==AF_INET6){
structisis_item_list*ipv6_reachs;if(spftree->mtid==ISIS_MT_IPV4_UNICAST)ipv6_rea
chs=&lsp->tlvs->ipv6_reach;elseipv6_reachs=isis_lookup_mt_items(&lsp->tlvs->mt_i
pv6_reach,spftree->mtid);structisis_ipv6_reach*r;for(r=ipv6_reachs?(structisis_i
pv6_reach*)ipv6_reachs->head:NULL;r;r=r->next){dist=cost+r->metric;vtype=r->exte
rnal?VTYPE_IP6REACH_EXTERNAL:VTYPE_IP6REACH_INTERNAL;process_N(spftree,vtype,(vo
id*)&r->prefix,dist,depth+1,parent);}}if(fragnode==NULL)fragnode=listhead(lsp->l
spu.frags);elsefragnode=listnextnode(fragnode);if(fragnode){lsp=listgetdata(frag
node);gotolspfragloop;}returnISIS_OK;}staticintisis_spf_preload_tent(structisis_
spftree*spftree,uint8_t*root_sysid,structisis_vertex*parent){structisis_circuit*
circuit;structlistnode*cnode,*anode,*ipnode;structisis_adjacency*adj;structisis_
lsp*lsp;structlist*adj_list;structlist*adjdb;structprefix_ipv4*ipv4;structprefix
prefix;intretval=ISIS_OK;uint8_tlsp_id[ISIS_SYS_ID_LEN+2];staticuint8_tnull_lsp_
id[ISIS_SYS_ID_LEN+2];structprefix_ipv6*ipv6;structisis_circuit_mt_setting*circu
it_mt;for(ALL_LIST_ELEMENTS_RO(spftree->area->circuit_list,cnode,circuit)){circu
it_mt=circuit_lookup_mt_setting(circuit,spftree->mtid);if(circuit_mt&&!circuit_m
t->enabled)continue;if(circuit->state!=C_STATE_UP)continue;if(!(circuit->is_type
&spftree->level))continue;if(spftree->family==AF_INET&&!circuit->ip_router)conti
nue;if(spftree->family==AF_INET6&&!circuit->ipv6_router)continue;/**AddIP(v6)add
ressesofthiscircuit*/if(spftree->family==AF_INET){prefix.family=AF_INET;for(ALL_
LIST_ELEMENTS_RO(circuit->ip_addrs,ipnode,ipv4)){prefix.u.prefix4=ipv4->prefix;p
refix.prefixlen=ipv4->prefixlen;apply_mask(&prefix);isis_spf_add_local(spftree,V
TYPE_IPREACH_INTERNAL,&prefix,NULL,0,parent);}}if(spftree->family==AF_INET6){pre
fix.family=AF_INET6;for(ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link,ipnode,ipv6)
){prefix.prefixlen=ipv6->prefixlen;prefix.u.prefix6=ipv6->prefix;apply_mask(&pre
fix);isis_spf_add_local(spftree,VTYPE_IP6REACH_INTERNAL,&prefix,NULL,0,parent);}
}if(circuit->circ_type==CIRCUIT_T_BROADCAST){/**Addtheadjacencies*/adj_list=list
_new();adjdb=circuit->u.bc.adjdb[spftree->level-1];isis_adj_build_up_list(adjdb,
adj_list);if(listcount(adj_list)==0){list_delete_and_null(&adj_list);if(isis->de
bugs&DEBUG_SPF_EVENTS)zlog_debug("ISIS-Spf:noL%dadjacenciesoncircuit%s",spftree-
>level,circuit->interface->name);continue;}for(ALL_LIST_ELEMENTS_RO(adj_list,ano
de,adj)){if(!adj_has_mt(adj,spftree->mtid))continue;if(spftree->mtid==ISIS_MT_IP
V4_UNICAST&&!speaks(adj->nlpids.nlpids,adj->nlpids.count,spftree->family))contin
ue;switch(adj->sys_type){caseISIS_SYSTYPE_ES:memcpy(lsp_id,adj->sysid,ISIS_SYS_I
D_LEN);LSP_PSEUDO_ID(lsp_id)=0;isis_spf_add_local(spftree,VTYPE_ES,lsp_id,adj,ci
rcuit->te_metric[spftree->level-1],parent);break;caseISIS_SYSTYPE_IS:caseISIS_SY
STYPE_L1_IS:caseISIS_SYSTYPE_L2_IS:memcpy(lsp_id,adj->sysid,ISIS_SYS_ID_LEN);LSP
_PSEUDO_ID(lsp_id)=0;LSP_FRAGMENT(lsp_id)=0;isis_spf_add_local(spftree,spftree->
area->oldmetric?VTYPE_NONPSEUDO_IS:VTYPE_NONPSEUDO_TE_IS,lsp_id,adj,circuit->te_
metric[spftree->level-1],parent);lsp=lsp_search(lsp_id,spftree->area->lspdb[spft
ree->level-1]);if(lsp==NULL||lsp->hdr.rem_lifetime==0)zlog_warn("ISIS-Spf:NoLSP%
sfoundforISadjacency""L%don%s(ID%u)",rawlspid_print(lsp_id),spftree->level,circu
it->interface->name,circuit->circuit_id);break;caseISIS_SYSTYPE_UNKNOWN:default:
zlog_warn("isis_spf_preload_tentunknowadjtype");}}list_delete_and_null(&adj_list
);/**Addthepseudonode*/if(spftree->level==1)memcpy(lsp_id,circuit->u.bc.l1_desig
_is,ISIS_SYS_ID_LEN+1);elsememcpy(lsp_id,circuit->u.bc.l2_desig_is,ISIS_SYS_ID_L
EN+1);/*canhappenduringDRreboot*/if(memcmp(lsp_id,null_lsp_id,ISIS_SYS_ID_LEN+1)
==0){if(isis->debugs&DEBUG_SPF_EVENTS)zlog_debug("ISIS-Spf:NoL%dDRon%s(ID%d)",sp
ftree->level,circuit->interface->name,circuit->circuit_id);continue;}adj=isis_ad
j_lookup(lsp_id,adjdb);/*ifnoadj,wearethedisorerror*/if(!adj&&!circuit->u.bc.is_
dr[spftree->level-1]){zlog_warn("ISIS-Spf:Noadjacencyfoundfromroot""toL%dDR%son%
s(ID%d)",spftree->level,rawlspid_print(lsp_id),circuit->interface->name,circuit-
>circuit_id);continue;}lsp=lsp_search(lsp_id,spftree->area->lspdb[spftree->level
-1]);if(lsp==NULL||lsp->hdr.rem_lifetime==0){zlog_warn("ISIS-Spf:Nolsp(%p)foundf
romroot""toL%dDR%son%s(ID%d)",(void*)lsp,spftree->level,rawlspid_print(lsp_id),c
ircuit->interface->name,circuit->circuit_id);continue;}isis_spf_process_lsp(spft
ree,lsp,circuit->te_metric[spftree->level-1],0,root_sysid,parent);}elseif(circui
t->circ_type==CIRCUIT_T_P2P){adj=circuit->u.p2p.neighbor;if(!adj||adj->adj_state
!=ISIS_ADJ_UP)continue;if(!adj_has_mt(adj,spftree->mtid))continue;switch(adj->sy
s_type){caseISIS_SYSTYPE_ES:memcpy(lsp_id,adj->sysid,ISIS_SYS_ID_LEN);LSP_PSEUDO
_ID(lsp_id)=0;isis_spf_add_local(spftree,VTYPE_ES,lsp_id,adj,circuit->te_metric[
spftree->level-1],parent);break;caseISIS_SYSTYPE_IS:caseISIS_SYSTYPE_L1_IS:caseI
SIS_SYSTYPE_L2_IS:memcpy(lsp_id,adj->sysid,ISIS_SYS_ID_LEN);LSP_PSEUDO_ID(lsp_id
)=0;LSP_FRAGMENT(lsp_id)=0;if(spftree->mtid!=ISIS_MT_IPV4_UNICAST||speaks(adj->n
lpids.nlpids,adj->nlpids.count,spftree->family))isis_spf_add_local(spftree,spftr
ee->area->oldmetric?VTYPE_NONPSEUDO_IS:VTYPE_NONPSEUDO_TE_IS,lsp_id,adj,circuit-
>te_metric[spftree->level-1],parent);break;caseISIS_SYSTYPE_UNKNOWN:default:zlog
_warn("isis_spf_preload_tentunknownadjtype");break;}}elseif(circuit->circ_type==
CIRCUIT_T_LOOPBACK){continue;}else{zlog_warn("isis_spf_preload_tentunsupportedme
dia");retval=ISIS_WARNING;}}returnretval;}/**Theparent(s)forvertexissetwhenadded
toTENTlist*nowwejustputthechildpointer(s)inplace*/staticvoidadd_to_paths(structi
sis_spftree*spftree,structisis_vertex*vertex){charbuff[PREFIX2STR_BUFFER];if(isi
s_find_vertex(&spftree->paths,vertex->N.id,vertex->type))return;isis_vertex_queu
e_append(&spftree->paths,vertex);#ifdefEXTREME_DEBUGzlog_debug("ISIS-Spf:added%s
%s%sdepth%ddist%dtoPATHS",print_sys_hostname(vertex->N.id),vtype2string(vertex->
type),vid2string(vertex,buff,sizeof(buff)),vertex->depth,vertex->d_N);#endif/*EX
TREME_DEBUG*/if(VTYPE_IP(vertex->type)){if(listcount(vertex->Adj_N)>0)isis_route
_create((structprefix*)&vertex->N.prefix,vertex->d_N,vertex->depth,vertex->Adj_N
,spftree->area,spftree->level);elseif(isis->debugs&DEBUG_SPF_EVENTS)zlog_debug("
ISIS-Spf:noadjacenciesdonotinstallroutefor""%sdepth%ddist%d",vid2string(vertex,b
uff,sizeof(buff)),vertex->depth,vertex->d_N);}return;}staticvoidinit_spt(structi
sis_spftree*spftree,intmtid,intlevel,intfamily){isis_vertex_queue_clear(&spftree
->tents);isis_vertex_queue_clear(&spftree->paths);spftree->mtid=mtid;spftree->le
vel=level;spftree->family=family;return;}staticintisis_run_spf(structisis_area*a
rea,intlevel,intfamily,uint8_t*sysid,structtimeval*nowtv){intretval=ISIS_OK;stru
ctisis_vertex*vertex;structisis_vertex*root_vertex;structisis_spftree*spftree=NU
LL;uint8_tlsp_id[ISIS_SYS_ID_LEN+2];structisis_lsp*lsp;structroute_table*table=N
ULL;structtimevaltime_now;unsignedlonglongstart_time,end_time;uint16_tmtid;/*Get
timethatcan'trollbackwards.*/start_time=nowtv->tv_sec;start_time=(start_time*100
0000)+nowtv->tv_usec;if(family==AF_INET)spftree=area->spftree[level-1];elseif(fa
mily==AF_INET6)spftree=area->spftree6[level-1];assert(spftree);assert(sysid);/*M
akeallroutesincurrentroutetableinactive.*/if(family==AF_INET)table=area->route_t
able[level-1];elseif(family==AF_INET6)table=area->route_table6[level-1];isis_rou
te_invalidate_table(area,table);/*Weonlysupportipv4-unicastandipv6-unicastastopo
logiesfornow*/if(family==AF_INET6)mtid=isis_area_ipv6_topology(area);elsemtid=IS
IS_MT_IPV4_UNICAST;/**C.2.5Step0*/init_spt(spftree,mtid,level,family);/*a)*/root
_vertex=isis_spf_add_root(spftree,sysid);/*b)*/retval=isis_spf_preload_tent(spft
ree,sysid,root_vertex);if(retval!=ISIS_OK){zlog_warn("ISIS-Spf:failedtoloadTENTS
PF-root:%s",print_sys_hostname(sysid));gotoout;}/**C.2.7Step2*/if(!isis_vertex_q
ueue_count(&spftree->tents)&&(isis->debugs&DEBUG_SPF_EVENTS)){zlog_warn("ISIS-Sp
f:TENTisemptySPF-root:%s",print_sys_hostname(sysid));}while(isis_vertex_queue_co
unt(&spftree->tents)){vertex=isis_vertex_queue_pop(&spftree->tents);#ifdefEXTREM
E_DEBUGzlog_debug("ISIS-Spf:getTENTnode%s%sdepth%ddist%dtoPATHS",print_sys_hostn
ame(vertex->N.id),vtype2string(vertex->type),vertex->depth,vertex->d_N);#endif/*
EXTREME_DEBUG*/add_to_paths(spftree,vertex);if(VTYPE_IS(vertex->type)){memcpy(ls
p_id,vertex->N.id,ISIS_SYS_ID_LEN+1);LSP_FRAGMENT(lsp_id)=0;lsp=lsp_search(lsp_i
d,area->lspdb[level-1]);if(lsp&&lsp->hdr.rem_lifetime!=0){isis_spf_process_lsp(s
pftree,lsp,vertex->d_N,vertex->depth,sysid,vertex);}else{zlog_warn("ISIS-Spf:NoL
SPfoundfor%s",rawlspid_print(lsp_id));}}}out:isis_route_validate(area);spftree->
runcount++;spftree->last_run_timestamp=time(NULL);spftree->last_run_monotime=mon
otime(&time_now);end_time=time_now.tv_sec;end_time=(end_time*1000000)+time_now.t
v_usec;spftree->last_run_duration=end_time-start_time;returnretval;}staticintisi
s_run_spf_cb(structthread*thread){structisis_spf_run*run=THREAD_ARG(thread);stru
ctisis_area*area=run->area;intlevel=run->level;intretval=ISIS_OK;XFREE(MTYPE_ISI
S_SPF_RUN,run);area->spf_timer[level-1]=NULL;if(!(area->is_type&level)){if(isis-
>debugs&DEBUG_SPF_EVENTS)zlog_warn("ISIS-SPF(%s)areadoesnotsharelevel",area->are
a_tag);returnISIS_WARNING;}if(isis->debugs&DEBUG_SPF_EVENTS)zlog_debug("ISIS-Spf
(%s)L%dSPFneeded,periodicSPF",area->area_tag,level);if(area->ip_circuits)retval=
isis_run_spf(area,level,AF_INET,isis->sysid,&thread->real);if(area->ipv6_circuit
s)retval=isis_run_spf(area,level,AF_INET6,isis->sysid,&thread->real);returnretva
l;}staticstructisis_spf_run*isis_run_spf_arg(structisis_area*area,intlevel){stru
ctisis_spf_run*run=XMALLOC(MTYPE_ISIS_SPF_RUN,sizeof(*run));run->area=area;run->
level=level;returnrun;}intisis_spf_schedule(structisis_area*area,intlevel){struc
tisis_spftree*spftree=area->spftree[level-1];time_tnow=monotime(NULL);intdiff=no
w-spftree->last_run_monotime;assert(diff>=0);assert(area->is_type&level);if(isis
->debugs&DEBUG_SPF_EVENTS)zlog_debug("ISIS-Spf(%s)L%dSPFschedulecalled,lastrun%d
secago",area->area_tag,level,diff);if(area->spf_delay_ietf[level-1]){/*Needtocal
lschedulefunctionalsoifspfdelayisrunning*to*restartholdofftimer-compare*draft-ie
tf-rtgwg-backoff-algo-04*/longdelay=spf_backoff_schedule(area->spf_delay_ietf[le
vel-1]);if(area->spf_timer[level-1])returnISIS_OK;thread_add_timer_msec(master,i
sis_run_spf_cb,isis_run_spf_arg(area,level),delay,&area->spf_timer[level-1]);ret
urnISIS_OK;}if(area->spf_timer[level-1])returnISIS_OK;/*waitconfiguredmin_spf_in
tervalbeforedoingtheSPF*/longtimer;if(diff>=area->min_spf_interval[level-1]){/*L
astrunismorethanminintervalago,scheduleimmediaterun*/timer=0;}else{timer=area->m
in_spf_interval[level-1]-diff;}thread_add_timer(master,isis_run_spf_cb,isis_run_
spf_arg(area,level),timer,&area->spf_timer[level-1]);if(isis->debugs&DEBUG_SPF_E
VENTS)zlog_debug("ISIS-Spf(%s)L%dSPFscheduled%ldsecfromnow",area->area_tag,level
,timer);returnISIS_OK;}staticvoidisis_print_paths(structvty*vty,structisis_verte
x_queue*queue,uint8_t*root_sysid){structlistnode*node;structisis_vertex*vertex;c
harbuff[PREFIX2STR_BUFFER];vty_out(vty,"VertexTypeMetricNext-HopInterfaceParent\
n");for(ALL_QUEUE_ELEMENTS_RO(queue,node,vertex)){if(memcmp(vertex->N.id,root_sy
sid,ISIS_SYS_ID_LEN)==0){vty_out(vty,"%-20s%-12s%-6s",print_sys_hostname(root_sy
sid),"","");vty_out(vty,"%-30s\n","");continue;}introws=0;structlistnode*anode=l
isthead(vertex->Adj_N);structlistnode*pnode=listhead(vertex->parents);structisis
_adjacency*adj;structisis_vertex*pvertex;vty_out(vty,"%-20s%-12s%-6u",vid2string
(vertex,buff,sizeof(buff)),vtype2string(vertex->type),vertex->d_N);for(unsignedi
nti=0;i<MAX(listcount(vertex->Adj_N),listcount(vertex->parents));i++){if(anode){
adj=listgetdata(anode);anode=anode->next;}else{adj=NULL;}if(pnode){pvertex=listg
etdata(pnode);pnode=pnode->next;}else{pvertex=NULL;}if(rows){vty_out(vty,"\n");v
ty_out(vty,"%-20s%-12s%-6s","","","");}if(adj){vty_out(vty,"%-20s%-9s",print_sys
_hostname(adj->sysid),adj->circuit->interface->name);}if(pvertex){if(!adj)vty_ou
t(vty,"%-20s%-9s","","");vty_out(vty,"%s(%d)",vid2string(pvertex,buff,sizeof(buf
f)),pvertex->type);}++rows;}vty_out(vty,"\n");}}DEFUN(show_isis_topology,show_is
is_topology_cmd,"showisistopology[<level-1|level-2>]",SHOW_STR"IS-ISinformation\
n""IS-ISpathstoIntermediateSystems\n""Pathstoalllevel-1routersinthearea\n""Paths
toalllevel-2routersinthedomain\n"){intlevels;structlistnode*node;structisis_area
*area;if(argc<4)levels=ISIS_LEVEL1|ISIS_LEVEL2;elseif(strmatch(argv[3]->text,"le
vel-1"))levels=ISIS_LEVEL1;elselevels=ISIS_LEVEL2;if(!isis->area_list||isis->are
a_list->count==0)returnCMD_SUCCESS;for(ALL_LIST_ELEMENTS_RO(isis->area_list,node
,area)){vty_out(vty,"Area%s:\n",area->area_tag?area->area_tag:"null");for(intlev
el=ISIS_LEVEL1;level<=ISIS_LEVELS;level++){if((level&levels)==0)continue;if(area
->ip_circuits>0&&area->spftree[level-1]&&isis_vertex_queue_count(&area->spftree[
level-1]->paths)>0){vty_out(vty,"IS-ISpathstolevel-%droutersthatspeakIP\n",level
);isis_print_paths(vty,&area->spftree[level-1]->paths,isis->sysid);vty_out(vty,"
\n");}if(area->ipv6_circuits>0&&area->spftree6[level-1]&&isis_vertex_queue_count
(&area->spftree6[level-1]->paths)>0){vty_out(vty,"IS-ISpathstolevel-%drouterstha
tspeakIPv6\n",level);isis_print_paths(vty,&area->spftree6[level-1]->paths,isis->
sysid);vty_out(vty,"\n");}}vty_out(vty,"\n");}returnCMD_SUCCESS;}voidisis_spf_cm
ds_init(){install_element(VIEW_NODE,&show_isis_topology_cmd);}voidisis_spf_print
(structisis_spftree*spftree,structvty*vty){vty_out(vty,"lastrunelapsed:");vty_ou
t_timestr(vty,spftree->last_run_timestamp);vty_out(vty,"\n");vty_out(vty,"lastru
nduration:%uusec\n",(uint32_t)spftree->last_run_duration);vty_out(vty,"runcount:
%u\n",spftree->runcount);}