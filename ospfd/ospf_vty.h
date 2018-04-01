/*OSPFVTYinterface.*Copyright(C)2000ToshiakiTakada**ThisfileispartofGNUZebra.**G
NUZebraisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGe
neralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(atyo
uroption)any*laterversion.**GNUZebraisdistributedinthehopethatitwillbeuseful,but
*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORA
PARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavere
ceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;i
fnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA021
10-1301USA*/#ifndef_QUAGGA_OSPF_VTY_H#define_QUAGGA_OSPF_VTY_H/*Macros.*/#define
VTY_GET_OSPF_AREA_ID(V,F,STR)\{\intretv;\retv=str2area_id((STR),&(V),&(F));\if(r
etv<0){\vty_out(vty,"%%InvalidOSPFareaID\n");\returnCMD_WARNING;\}\}#defineVTY_G
ET_OSPF_AREA_ID_NO_BB(NAME,V,F,STR)\{\intretv;\retv=str2area_id((STR),&(V),&(F))
;\if(retv<0){\vty_out(vty,"%%InvalidOSPFareaID\n");\returnCMD_WARNING;\}\if(OSPF
_IS_AREA_ID_BACKBONE((V))){\vty_out(vty,\"%%Youcan'tconfigure%stobackbone\n",\NA
ME);\returnCMD_WARNING;\}\}/*Prototypes.*/externvoidospf_vty_init(void);externvo
idospf_vty_show_init(void);externvoidospf_vty_clear_init(void);externintstr2area
_id(constchar*,structin_addr*,int*);externvoidarea_id2str(char*,int,structin_add
r*,int);#endif/*_QUAGGA_OSPF_VTY_H*/