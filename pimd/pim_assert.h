/**PIMforQuagga*Copyright(C)2008EvertondaSilvaMarques**Thisprogramisfreesoftware
;youcanredistributeitand/ormodify*itunderthetermsoftheGNUGeneralPublicLicenseasp
ublishedby*theFreeSoftwareFoundation;eitherversion2oftheLicense,or*(atyouroption
)anylaterversion.**Thisprogramisdistributedinthehopethatitwillbeuseful,but*WITHO
UTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTIC
ULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavereceived
acopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,w
ritetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-130
1USA*/#ifndefPIM_ASSERT_H#definePIM_ASSERT_H#include<zebra.h>#include"if.h"#incl
ude"pim_neighbor.h"#include"pim_ifchannel.h"/*RFC4601:4.11.TimerValuesNotethatfo
rhistoricalreasons,theAssertmessagelacksaHoldtimefield.Thus,changingtheAssertTim
efromthedefaultvalueisnotrecommended.*/#definePIM_ASSERT_OVERRIDE_INTERVAL(3)/*s
econds*/#definePIM_ASSERT_TIME(180)/*seconds*/#definePIM_ASSERT_METRIC_PREFERENC
E_MAX(0xFFFFFFFF)#definePIM_ASSERT_ROUTE_METRIC_MAX(0xFFFFFFFF)voidpim_ifassert_
winner_set(structpim_ifchannel*ch,enumpim_ifassert_statenew_state,structin_addrw
inner,structpim_assert_metricwinner_metric);intpim_assert_recv(structinterface*i
fp,structpim_neighbor*neigh,structin_addrsrc_addr,uint8_t*buf,intbuf_size);intpi
m_assert_metric_better(conststructpim_assert_metric*m1,conststructpim_assert_met
ric*m2);intpim_assert_metric_match(conststructpim_assert_metric*m1,conststructpi
m_assert_metric*m2);intpim_assert_build_msg(uint8_t*pim_msg,intbuf_size,structin
terface*ifp,structin_addrgroup_addr,structin_addrsource_addr,uint32_tmetric_pref
erence,uint32_troute_metric,uint32_trpt_bit_flag);intpim_assert_send(structpim_i
fchannel*ch);intassert_action_a1(structpim_ifchannel*ch);voidassert_action_a4(st
ructpim_ifchannel*ch);voidassert_action_a5(structpim_ifchannel*ch);#endif/*PIM_A
SSERT_H*/