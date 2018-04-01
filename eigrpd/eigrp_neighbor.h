/**EIGRPNeighborHandling.*Copyright(C)2013-2016*Authors:*DonnieSavage*JanJanovic
*MatejPerina*PeterOrsag*PeterPaluch*FrantisekGazo*TomasHvorkovy*MartinKontsek*Lu
kasKoribsky**ThisfileispartofGNUZebra.**GNUZebraisfreesoftware;youcanredistribut
eitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*Free
SoftwareFoundation;eitherversion2,or(atyouroption)any*laterversion.**GNUZebraisd
istributedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpli
edwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPubl
icLicenseformoredetails.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicense
along*withthisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,
Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#ifndef_ZEBRA_EIGRP_NEIGHBO
R_H#define_ZEBRA_EIGRP_NEIGHBOR_H/*Prototypes*/externstructeigrp_neighbor*eigrp_
nbr_get(structeigrp_interface*,structeigrp_header*,structip*);externstructeigrp_
neighbor*eigrp_nbr_new(structeigrp_interface*);externvoideigrp_nbr_delete(struct
eigrp_neighbor*);externintholddown_timer_expired(structthread*);externinteigrp_n
eighborship_check(structeigrp_neighbor*,structTLV_Parameter_Type*);externvoideig
rp_nbr_state_update(structeigrp_neighbor*);externvoideigrp_nbr_state_set(structe
igrp_neighbor*,uint8_tstate);externuint8_teigrp_nbr_state_get(structeigrp_neighb
or*);externinteigrp_nbr_count_get(void);externconstchar*eigrp_nbr_state_str(stru
cteigrp_neighbor*);externstructeigrp_neighbor*eigrp_nbr_lookup_by_addr(structeig
rp_interface*,structin_addr*);externstructeigrp_neighbor*eigrp_nbr_lookup_by_add
r_process(structeigrp*,structin_addr);externvoideigrp_nbr_hard_restart(structeig
rp_neighbor*nbr,structvty*vty);externinteigrp_nbr_split_horizon_check(structeigr
p_nexthop_entry*ne,structeigrp_interface*ei);#endif/*_ZEBRA_EIGRP_NEIGHBOR_H*/