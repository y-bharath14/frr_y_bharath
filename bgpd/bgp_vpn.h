/*VPNcommonfunctionstoMP-BGP*Copyright(C)20176WIND**ThisfileispartofFRRouting.**
FRRoutingisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNU
GeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(at
youroption)any*laterversion.**FRRoutingisdistributedinthehopethatitwillbeuseful,
but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSF
ORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhav
ereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYIN
G;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA
02110-1301USA*/#ifndef_FRR_BGP_VPN_H#define_FRR_BGP_VPN_H#include<zebra.h>extern
intshow_adj_route_vpn(structvty*vty,structpeer*peer,structprefix_rd*prd,afi_tafi
,safi_tsafi,uint8_tuse_json);#endif/*_QUAGGA_BGP_VPN_H*/