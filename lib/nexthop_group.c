/**NexthopGroupstructuredefinition.*Copyright(C)2018CumulusNetworks,Inc.*DonaldS
harp**Thisprogramisfreesoftware;youcanredistributeitand/ormodifyit*undertheterms
oftheGNUGeneralPublicLicenseaspublishedbytheFree*SoftwareFoundation;eitherversio
n2oftheLicense,or(atyouroption)*anylaterversion.**Thisprogramisdistributedintheh
opethatitwillbeuseful,butWITHOUT*ANYWARRANTY;withouteventheimpliedwarrantyofMERC
HANTABILITYor*FITNESSFORAPARTICULARPURPOSE.SeetheGNUGeneralPublicLicensefor*more
details.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthispr
ogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinS
t,FifthFloor,Boston,MA02110-1301USA*/#include<zebra.h>#include<vrf.h>#include<ne
xthop.h>#include<nexthop_group.h>#include<vty.h>#include<command.h>#ifndefVTYSH_
EXTRACT_PL#include"lib/nexthop_group_clippy.c"#endifDEFINE_MTYPE_STATIC(LIB,NEXT
HOP_GROUP,"NexthopGroup")structnexthop_group_hooks{void(*new)(constchar*name);vo
id(*add_nexthop)(conststructnexthop_group_cmd*nhg,conststructnexthop*nhop);void(
*del_nexthop)(conststructnexthop_group_cmd*nhg,conststructnexthop*nhop);void(*de
lete)(constchar*name);};staticstructnexthop_group_hooksnhg_hooks;staticinlineint
nexthop_group_cmd_compare(conststructnexthop_group_cmd*nhgc1,conststructnexthop_
group_cmd*nhgc2);RB_GENERATE(nhgc_entry_head,nexthop_group_cmd,nhgc_entry,nextho
p_group_cmd_compare)structnhgc_entry_headnhgc_entries;staticinlineintnexthop_gro
up_cmd_compare(conststructnexthop_group_cmd*nhgc1,conststructnexthop_group_cmd*n
hgc2){returnstrcmp(nhgc1->name,nhgc2->name);}structnexthop*nexthop_exists(struct
nexthop_group*nhg,structnexthop*nh){structnexthop*nexthop;for(nexthop=nhg->nexth
op;nexthop;nexthop=nexthop->next){if(nexthop_same(nh,nexthop))returnnexthop;}ret
urnNULL;}structnexthop_group*nexthop_group_new(void){returnXCALLOC(MTYPE_NEXTHOP
_GROUP,sizeof(structnexthop_group));}voidnexthop_group_delete(structnexthop_grou
p**nhg){XFREE(MTYPE_NEXTHOP_GROUP,*nhg);}/*Addnexthoptotheendofanexthoplist.*/vo
idnexthop_add(structnexthop**target,structnexthop*nexthop){structnexthop*last;fo
r(last=*target;last&&last->next;last=last->next);if(last)last->next=nexthop;else
*target=nexthop;nexthop->prev=last;}/*Deletenexthopfromanexthoplist.*/voidnextho
p_del(structnexthop_group*nhg,structnexthop*nh){structnexthop*nexthop;for(nextho
p=nhg->nexthop;nexthop;nexthop=nexthop->next){if(nexthop_same(nh,nexthop))break;
}assert(nexthop);if(nexthop->prev)nexthop->prev->next=nexthop->next;elsenhg->nex
thop=nexthop->next;if(nexthop->next)nexthop->next->prev=nexthop->prev;}voidcopy_
nexthops(structnexthop**tnh,structnexthop*nh,structnexthop*rparent){structnextho
p*nexthop;structnexthop*nh1;for(nh1=nh;nh1;nh1=nh1->next){nexthop=nexthop_new();
nexthop->vrf_id=nh1->vrf_id;nexthop->ifindex=nh1->ifindex;nexthop->type=nh1->typ
e;nexthop->flags=nh1->flags;memcpy(&nexthop->gate,&nh1->gate,sizeof(nh1->gate));
memcpy(&nexthop->src,&nh1->src,sizeof(nh1->src));memcpy(&nexthop->rmap_src,&nh1-
>rmap_src,sizeof(nh1->rmap_src));nexthop->rparent=rparent;if(nh1->nh_label)nexth
op_add_labels(nexthop,nh1->nh_label_type,nh1->nh_label->num_labels,&nh1->nh_labe
l->label[0]);nexthop_add(tnh,nexthop);if(CHECK_FLAG(nh1->flags,NEXTHOP_FLAG_RECU
RSIVE))copy_nexthops(&nexthop->resolved,nh1->resolved,nexthop);}}staticvoidnhgc_
delete_nexthops(structnexthop_group_cmd*nhgc){structnexthop*nexthop;nexthop=nhgc
->nhg.nexthop;while(nexthop){structnexthop*next=nexthop_next(nexthop);if(nhg_hoo
ks.del_nexthop)nhg_hooks.del_nexthop(nhgc,nexthop);nexthop_free(nexthop);nexthop
=next;}}structnexthop_group_cmd*nhgc_find(constchar*name){structnexthop_group_cm
dfind;strlcpy(find.name,name,sizeof(find.name));returnRB_FIND(nhgc_entry_head,&n
hgc_entries,&find);}staticstructnexthop_group_cmd*nhgc_get(constchar*name){struc
tnexthop_group_cmd*nhgc;nhgc=nhgc_find(name);if(!nhgc){nhgc=XCALLOC(MTYPE_TMP,si
zeof(*nhgc));strlcpy(nhgc->name,name,sizeof(nhgc->name));QOBJ_REG(nhgc,nexthop_g
roup_cmd);RB_INSERT(nhgc_entry_head,&nhgc_entries,nhgc);if(nhg_hooks.new)nhg_hoo
ks.new(name);}returnnhgc;}staticvoidnhgc_delete(structnexthop_group_cmd*nhgc){nh
gc_delete_nexthops(nhgc);if(nhg_hooks.delete)nhg_hooks.delete(nhgc->name);RB_REM
OVE(nhgc_entry_head,&nhgc_entries,nhgc);}DEFINE_QOBJ_TYPE(nexthop_group_cmd)DEFU
N_NOSH(nexthop_group,nexthop_group_cmd,"nexthop-groupNAME","Enterintothenexthop-
groupsubmode\n""SpecifytheNAMEofthenexthop-group\n"){constchar*nhg_name=argv[1]-
>arg;structnexthop_group_cmd*nhgc=NULL;nhgc=nhgc_get(nhg_name);VTY_PUSH_CONTEXT(
NH_GROUP_NODE,nhgc);returnCMD_SUCCESS;}DEFUN_NOSH(no_nexthop_group,no_nexthop_gr
oup_cmd,"nonexthop-groupNAME",NO_STR"Deletethenexthop-group\n""SpecifytheNAMEoft
henexthop-group\n"){constchar*nhg_name=argv[2]->arg;structnexthop_group_cmd*nhgc
=NULL;nhgc=nhgc_find(nhg_name);if(nhgc)nhgc_delete(nhgc);returnCMD_SUCCESS;}DEFP
Y(ecmp_nexthops,ecmp_nexthops_cmd,"[no]nexthop<A.B.C.D|X:X::X:X>$addr[INTERFACE]
$intf[nexthop-vrfNAME$name]",NO_STR"SpecifyoneofthenexthopsinthisECMPgroup\n""v4
Address\n""v6Address\n""Interfacetouse\n""Ifthenexthopisinadifferentvrftellus\n"
"Thenexthop-vrfName\n"){VTY_DECLVAR_CONTEXT(nexthop_group_cmd,nhgc);structvrf*vr
f;structnexthopnhop;structnexthop*nh;if(name)vrf=vrf_lookup_by_name(name);elsevr
f=vrf_lookup_by_id(VRF_DEFAULT);if(!vrf){vty_out(vty,"Specified:%sisnon-existent
\n",name);returnCMD_WARNING;}memset(&nhop,0,sizeof(nhop));nhop.vrf_id=vrf->vrf_i
d;if(addr->sa.sa_family==AF_INET){nhop.gate.ipv4.s_addr=addr->sin.sin_addr.s_add
r;if(intf){nhop.type=NEXTHOP_TYPE_IPV4_IFINDEX;nhop.ifindex=ifname2ifindex(intf,
vrf->vrf_id);if(nhop.ifindex==IFINDEX_INTERNAL){vty_out(vty,"SpecifiedIntf%sdoes
notexistinvrf:%s\n",intf,vrf->name);returnCMD_WARNING;}}elsenhop.type=NEXTHOP_TY
PE_IPV4;}else{memcpy(&nhop.gate.ipv6,&addr->sin6.sin6_addr,16);if(intf){nhop.typ
e=NEXTHOP_TYPE_IPV6_IFINDEX;nhop.ifindex=ifname2ifindex(intf,vrf->vrf_id);if(nho
p.ifindex==IFINDEX_INTERNAL){vty_out(vty,"SpecifiedIntf%sdoesnotexistinvrf:%s\n"
,intf,vrf->name);returnCMD_WARNING;}}elsenhop.type=NEXTHOP_TYPE_IPV6;}nh=nexthop
_exists(&nhgc->nhg,&nhop);if(no){if(nh){nexthop_del(&nhgc->nhg,nh);if(nhg_hooks.
del_nexthop)nhg_hooks.del_nexthop(nhgc,nh);nexthop_free(nh);}}elseif(!nh){/*must
beaddingnewnexthopsince!noand!nexthop_exists*/nh=nexthop_new();memcpy(nh,&nhop,s
izeof(nhop));nexthop_add(&nhgc->nhg.nexthop,nh);if(nhg_hooks.add_nexthop)nhg_hoo
ks.add_nexthop(nhgc,nh);}returnCMD_SUCCESS;}structcmd_nodenexthop_group_node={NH
_GROUP_NODE,"%s(config-nh-group)#",1};voidnexthop_group_write_nexthop(structvty*
vty,structnexthop*nh){charbuf[100];structvrf*vrf;vty_out(vty,"nexthop");switch(n
h->type){caseNEXTHOP_TYPE_IFINDEX:vty_out(vty,"%s",ifindex2ifname(nh->ifindex,nh
->vrf_id));break;caseNEXTHOP_TYPE_IPV4:vty_out(vty,"%s",inet_ntoa(nh->gate.ipv4)
);break;caseNEXTHOP_TYPE_IPV4_IFINDEX:vty_out(vty,"%s%s",inet_ntoa(nh->gate.ipv4
),ifindex2ifname(nh->ifindex,nh->vrf_id));break;caseNEXTHOP_TYPE_IPV6:vty_out(vt
y,"%s",inet_ntop(AF_INET6,&nh->gate.ipv6,buf,sizeof(buf)));break;caseNEXTHOP_TYP
E_IPV6_IFINDEX:vty_out(vty,"%s%s",inet_ntop(AF_INET6,&nh->gate.ipv6,buf,sizeof(b
uf)),ifindex2ifname(nh->ifindex,nh->vrf_id));break;caseNEXTHOP_TYPE_BLACKHOLE:br
eak;}if(nh->vrf_id!=VRF_DEFAULT){vrf=vrf_lookup_by_id(nh->vrf_id);vty_out(vty,"n
exthop-vrf%s",vrf->name);}vty_out(vty,"\n");}staticintnexthop_group_write(struct
vty*vty){structnexthop_group_cmd*nhgc;structnexthop*nh;RB_FOREACH(nhgc,nhgc_entr
y_head,&nhgc_entries){vty_out(vty,"nexthop-group%s\n",nhgc->name);for(nh=nhgc->n
hg.nexthop;nh;nh=nh->next)nexthop_group_write_nexthop(vty,nh);vty_out(vty,"!\n")
;}return1;}voidnexthop_group_init(void(*new)(constchar*name),void(*add_nexthop)(
conststructnexthop_group_cmd*nhg,conststructnexthop*nhop),void(*del_nexthop)(con
ststructnexthop_group_cmd*nhg,conststructnexthop*nhop),void(*delete)(constchar*n
ame)){RB_INIT(nhgc_entry_head,&nhgc_entries);install_node(&nexthop_group_node,ne
xthop_group_write);install_element(CONFIG_NODE,&nexthop_group_cmd);install_eleme
nt(CONFIG_NODE,&no_nexthop_group_cmd);install_default(NH_GROUP_NODE);install_ele
ment(NH_GROUP_NODE,&ecmp_nexthops_cmd);memset(&nhg_hooks,0,sizeof(nhg_hooks));if
(new)nhg_hooks.new=new;if(add_nexthop)nhg_hooks.add_nexthop=add_nexthop;if(del_n
exthop)nhg_hooks.del_nexthop=del_nexthop;if(delete)nhg_hooks.delete=delete;}