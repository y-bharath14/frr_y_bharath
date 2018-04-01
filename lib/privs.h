/**Zebraprivilegesheader.**Copyright(C)2003PaulJakma.**ThisfileispartofGNUZebra.
**GNUZebraisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGN
UGeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(a
tyouroption)any*laterversion.**GNUZebraisdistributedinthehopethatitwillbeuseful,
but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSF
ORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhav
ereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYIN
G;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA
02110-1301USA*/#ifndef_ZEBRA_PRIVS_H#define_ZEBRA_PRIVS_H/*listofzebracapabiliti
es*/typedefenum{ZCAP_SETID,ZCAP_BIND,ZCAP_NET_ADMIN,ZCAP_SYS_ADMIN,ZCAP_NET_RAW,
ZCAP_CHROOT,ZCAP_NICE,ZCAP_PTRACE,ZCAP_DAC_OVERRIDE,ZCAP_READ_SEARCH,ZCAP_FOWNER
,ZCAP_MAX}zebra_capabilities_t;typedefenum{ZPRIVS_LOWERED,ZPRIVS_RAISED,ZPRIVS_U
NKNOWN,}zebra_privs_current_t;typedefenum{ZPRIVS_RAISE,ZPRIVS_LOWER,}zebra_privs
_ops_t;structzebra_privs_t{zebra_capabilities_t*caps_p;/*capsrequiredforoperatio
n*/zebra_capabilities_t*caps_i;/*capstoallowinheritanceof*/intcap_num_p;/*number
ofcapsinarrays*/intcap_num_i;constchar*user;/*userandgrouptorunas*/constchar*gro
up;constchar*vty_group;/*grouptochownvtysocketto*//*methods*/int(*change)(zebra_
privs_ops_t);/*changeprivileges,0onsuccess*/zebra_privs_current_t(*current_state
)(void);/*currentprivilegestate*/};structzprivs_ids_t{/*-1isundefined*/uid_tuid_
priv;/*privilegeduid*/uid_tuid_normal;/*normaluid*/gid_tgid_priv;/*privilegeduid
*/gid_tgid_normal;/*normaluid*/gid_tgid_vty;/*vtygid*/};/*initialisezebraprivile
ges*/externvoidzprivs_preinit(structzebra_privs_t*zprivs);externvoidzprivs_init(
structzebra_privs_t*zprivs);/*dropallandterminateprivileges*/externvoidzprivs_te
rminate(structzebra_privs_t*);/*queryforruntimeuid'sandgid's,egvtyneedsthis*/ext
ernvoidzprivs_get_ids(structzprivs_ids_t*);#endif/*_ZEBRA_PRIVS_H*/