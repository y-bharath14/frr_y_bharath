/**EIGRPInterfaceFunctions.*Copyright(C)2013-2016*Authors:*DonnieSavage*JanJanov
ic*MatejPerina*PeterOrsag*PeterPaluch*FrantisekGazo*TomasHvorkovy*MartinKontsek*
LukasKoribsky**ThisfileispartofGNUZebra.**GNUZebraisfreesoftware;youcanredistrib
uteitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*Fr
eeSoftwareFoundation;eitherversion2,or(atyouroption)any*laterversion.**GNUZebrai
sdistributedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimp
liedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPu
blicLicenseformoredetails.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicen
sealong*withthisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundatio
n,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#ifndef_ZEBRA_EIGRP_INTER
FACE_H_#define_ZEBRA_EIGRP_INTERFACE_H_/*Prototypes*/externvoideigrp_if_init(voi
d);externinteigrp_if_new_hook(structinterface*);externinteigrp_if_delete_hook(st
ructinterface*);externbooleigrp_if_is_passive(structeigrp_interface*ei);externvo
ideigrp_del_if_params(structeigrp_if_params*);externstructeigrp_interface*eigrp_
if_new(structeigrp*,structinterface*,structprefix*);externinteigrp_if_up(structe
igrp_interface*);externvoideigrp_if_stream_set(structeigrp_interface*);externvoi
deigrp_if_set_multicast(structeigrp_interface*);externuint8_teigrp_default_iftyp
e(structinterface*);externvoideigrp_if_free(structeigrp_interface*,int);externin
teigrp_if_down(structeigrp_interface*);externvoideigrp_if_stream_unset(structeig
rp_interface*);externstructeigrp_interface*eigrp_if_lookup_by_local_addr(structe
igrp*,structinterface*,structin_addr);externstructeigrp_interface*eigrp_if_looku
p_by_name(structeigrp*,constchar*);/*Simulatedown/upontheinterface.*/externvoide
igrp_if_reset(structinterface*);externuint32_teigrp_bandwidth_to_scaled(uint32_t
);externuint32_teigrp_scaled_to_bandwidth(uint32_t);externuint32_teigrp_delay_to
_scaled(uint32_t);externuint32_teigrp_scaled_to_delay(uint32_t);#endif/*ZEBRA_EI
GRP_INTERFACE_H_*/