/**VRFrelatedheader.*Copyright(C)20146WINDS.A.**ThisfileispartofGNUZebra.**GNUZe
braisfreesoftware;youcanredistributeitand/ormodify*itunderthetermsoftheGNUGenera
lPublicLicenseaspublished*bytheFreeSoftwareFoundation;eitherversion2,or(atyour*o
ption)anylaterversion.**GNUZebraisdistributedinthehopethatitwillbeuseful,but*WIT
HOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPART
ICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavereceiv
edacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot
,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1
301USA*/#ifndef_ZEBRA_VRF_H#define_ZEBRA_VRF_H#include"openbsd-tree.h"#include"l
inklist.h"#include"qobj.h"#include"vty.h"#include"ns.h"/*ThedefaultVRFID*/#defin
eVRF_UNKNOWNUINT32_MAX/*Pending:Mayneedtorefinethis.*/#ifndefIFLA_VRF_MAXenum{IF
LA_VRF_UNSPEC,IFLA_VRF_TABLE,__IFLA_VRF_MAX};#defineIFLA_VRF_MAX(__IFLA_VRF_MAX-
1)#endif#defineVRF_NAMSIZ36#defineNS_NAMSIZ16#defineVRF_DEFAULT_NAME"Default-IP-
Routing-Table"/**Thecommandstrings*/#defineVRF_CMD_HELP_STR"SpecifytheVRF\nTheVR
Fname\n"#defineVRF_ALL_CMD_HELP_STR"SpecifytheVRF\nAllVRFs\n"#defineVRF_FULL_CMD
_HELP_STR"SpecifytheVRF\nTheVRFname\nAllVRFs\n"/**PasssomeOSspecificdataupthroug
h*tothedaemons*/structvrf_data{union{struct{uint32_ttable_id;charnetns_name[NS_N
AMSIZ];}l;};};structvrf{RB_ENTRY(vrf)id_entry,name_entry;/*Identifier,sameasthev
ectorindex*/vrf_id_tvrf_id;/*Name*/charname[VRF_NAMSIZ+1];/*ZebrainternalVRFstat
us*/uint8_tstatus;#defineVRF_ACTIVE(1<<0)/*VRFisupinkernel*/#defineVRF_CONFIGURE
D(1<<1)/*VRFhassomeFRRconfiguration*//*InterfacesbelongingtothisVRF*/structif_na
me_headifaces_by_name;structif_index_headifaces_by_index;/*Userdata*/void*info;/
*Thetable_idfromthekernel*/structvrf_datadata;/*Backpointertonamespacecontext*/v
oid*ns_ctxt;QOBJ_FIELDS};RB_HEAD(vrf_id_head,vrf);RB_PROTOTYPE(vrf_id_head,vrf,i
d_entry,vrf_id_compare)RB_HEAD(vrf_name_head,vrf);RB_PROTOTYPE(vrf_name_head,vrf
,name_entry,vrf_name_compare)DECLARE_QOBJ_TYPE(vrf)/*AllowVRFwithnetnsasbackend*
/#defineVRF_BACKEND_VRF_LITE0#defineVRF_BACKEND_NETNS1externstructvrf_id_headvrf
s_by_id;externstructvrf_name_headvrfs_by_name;externstructvrf*vrf_lookup_by_id(v
rf_id_t);externstructvrf*vrf_lookup_by_name(constchar*);externstructvrf*vrf_get(
vrf_id_t,constchar*);externconstchar*vrf_id_to_name(vrf_id_tvrf_id);externvrf_id
_tvrf_name_to_id(constchar*);#defineVRF_GET_ID(V,NAME)\do{\structvrf*vrf;\if(!(v
rf=vrf_lookup_by_name(NAME))){\vty_out(vty,"%%VRF%snotfound\n",NAME);\returnCMD_
WARNING;\}\if(vrf->vrf_id==VRF_UNKNOWN){\vty_out(vty,"%%VRF%snotactive\n",NAME);
\returnCMD_WARNING;\}\(V)=vrf->vrf_id;\}while(0)/**CheckwhethertheVRFisenabled.*
/staticinlineintvrf_is_enabled(structvrf*vrf){returnvrf&&CHECK_FLAG(vrf->status,
VRF_ACTIVE);}/*checkifthevrfisuserconfigured*/staticinlineintvrf_is_user_cfged(s
tructvrf*vrf){returnvrf&&CHECK_FLAG(vrf->status,VRF_CONFIGURED);}/*MarkthatVRFha
suserconfiguration*/staticinlinevoidvrf_set_user_cfged(structvrf*vrf){SET_FLAG(v
rf->status,VRF_CONFIGURED);}/*MarkthatVRFnolongerhasanyuserconfiguration*/static
inlinevoidvrf_reset_user_cfged(structvrf*vrf){UNSET_FLAG(vrf->status,VRF_CONFIGU
RED);}/**Utilitiestoobtaintheuserdata*//*GetthedatapointerofthespecifiedVRF.Ifno
tfound,createone.*/externvoid*vrf_info_get(vrf_id_t);/*Lookupthedatapointerofthe
specifiedVRF.*/externvoid*vrf_info_lookup(vrf_id_t);/**VRFbit-map:maintainingfla
gs,onebitperVRFID*/typedefvoid*vrf_bitmap_t;#defineVRF_BITMAP_NULLNULLexternvrf_
bitmap_tvrf_bitmap_init(void);externvoidvrf_bitmap_free(vrf_bitmap_t);externvoid
vrf_bitmap_set(vrf_bitmap_t,vrf_id_t);externvoidvrf_bitmap_unset(vrf_bitmap_t,vr
f_id_t);externintvrf_bitmap_check(vrf_bitmap_t,vrf_id_t);/**VRFinitializer/destr
uctor**create->CalledbackwhenanewVRFiscreated.This*canbeeitherthroughthese3optio
ns:*1)CLImentionsavrfbeforeOSknowsaboutit*2)OScallszebraandwecreatethevrffromOS*
callback*3)zebracallsindividualprotocolstonotify*aboutthenewvrf**enable->Calledb
ackwhenaVRFisactuallyusablefrom*anOSperspective(2and3above)**disable->Calledback
whenaVRFisbeingdeletedfrom*thesystem(2and3)above**delete->Calledbackwhenavrfisbe
ingdeletedfrom*thesystem(2and3)above.*/externvoidvrf_init(int(*create)(structvrf
*),int(*enable)(structvrf*),int(*disable)(structvrf*),int(*delete)(structvrf*));
/**Callvrf_terminatewhentheprotocolisbeingshutdown*/externvoidvrf_terminate(void
);/**Utilitiestocreatenetworksobjects,*orcallnetworkoperations*//*Createasockets
ervingforthegivenVRF*/externintvrf_socket(intdomain,inttype,intprotocol,vrf_id_t
vrf_id,char*name);externintvrf_sockunion_socket(constunionsockunion*su,vrf_id_tv
rf_id,char*name);externintvrf_bind(vrf_id_tvrf_id,intfd,char*name);/*VRFioctlope
rations*/externintvrf_getaddrinfo(constchar*node,constchar*service,conststructad
drinfo*hints,structaddrinfo**res,vrf_id_tvrf_id);externintvrf_ioctl(vrf_id_tvrf_
id,intd,unsignedlongrequest,char*args);/*functioncalledbymacroVRF_DEFAULT*togett
hedefaultVRF_ID*/externvrf_id_tvrf_get_default_id(void);/*ThedefaultVRFID*/#defi
neVRF_DEFAULTvrf_get_default_id()/*VRFismappedonnetnsornot?*/intvrf_is_mapped_on
_netns(vrf_id_tvrf_id);/*VRFswitchfromNETNS*/externintvrf_switch_to_netns(vrf_id
_tvrf_id);externintvrf_switchback_to_initial(void);/**VRFbackendroutines*shouldb
ecalledfromzebraonly*//*VRFvtycommandinitialisation*/externvoidvrf_cmd_init(int(
*writefunc)(structvty*vty),structzebra_privs_t*daemon_priv);/*VRFvtydebugging*/e
xternvoidvrf_install_commands(void);/**VRFutilities*//*APIforconfiguringVRFbacke
nd*shouldbecalledfromzebraonly*/externvoidvrf_configure_backend(intvrf_backend_n
etns);externintvrf_get_backend(void);externintvrf_is_backend_netns(void);/*APIto
createaVRF.eitherfromvty*orthroughdiscovery*/externintvrf_handler_create(structv
ty*vty,constchar*name,structvrf**vrf);/*APItoassociateaVRFwithaNETNS.*calledeith
erfromvtyorthroughdiscovery*shouldbecalledfromzebraonly*/externintvrf_netns_hand
ler_create(structvty*vty,structvrf*vrf,char*pathname,ns_id_tns_id);/*usedinterna
llytoenableordisableVRF.*NotifyachangeintheVRFIDoftheVRF*/externvoidvrf_disable(
structvrf*vrf);externintvrf_enable(structvrf*vrf);externvoidvrf_delete(structvrf
*vrf);#endif/*_ZEBRA_VRF_H*/