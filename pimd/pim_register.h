/**PIMforQuagga*Copyright(C)2015CumulusNetworks,Inc.*DonaldSharp**Thisprogramisf
reesoftware;youcanredistributeitand/ormodify*itunderthetermsoftheGNUGeneralPubli
cLicenseaspublishedby*theFreeSoftwareFoundation;eitherversion2oftheLicense,or*(a
tyouroption)anylaterversion.**Thisprogramisdistributedinthehopethatitwillbeusefu
l,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNES
SFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldh
avereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPY
ING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,
MA02110-1301USA*/#ifndefPIM_REGISTER_H#definePIM_REGISTER_H#include<zebra.h>#inc
lude"if.h"#definePIM_REGISTER_BORDER_BIT0x80000000#definePIM_REGISTER_NR_BIT0x40
000000#definePIM_MSG_REGISTER_LEN(8)#definePIM_MSG_REGISTER_STOP_LEN(4)intpim_re
gister_stop_recv(structinterface*ifp,uint8_t*buf,intbuf_size);intpim_register_re
cv(structinterface*ifp,structin_addrdest_addr,structin_addrsrc_addr,uint8_t*tlv_
buf,inttlv_buf_size);voidpim_register_send(constuint8_t*buf,intbuf_size,structin
_addrsrc,structpim_rpf*rpg,intnull_register,structpim_upstream*up);voidpim_regis
ter_stop_send(structinterface*ifp,structprefix_sg*sg,structin_addrsrc,structin_a
ddroriginator);voidpim_register_join(structpim_upstream*up);#endif