/**fpm_pb.h**@copyrightCopyright(C)2016SprouteNetworks,Inc.**@authorAvneeshSachd
ev<avneesh@sproute.com>**ThisfileispartofQuagga.**Quaggaisfreesoftware;youcanred
istributeitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicenseaspublishedby
the*FreeSoftwareFoundation;eitherversion2,or(atyouroption)any*laterversion.**Qua
ggaisdistributedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventh
eimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*Gener
alPublicLicenseformoredetails.**YoushouldhavereceivedacopyoftheGNUGeneralPublicL
icensealong*withthisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Found
ation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*//**Publicheaderfilefo
rfpmprotobufdefinitions.*/#ifndef_FPM_PB_H#define_FPM_PB_H#include"route_types.h
"#include"qpb/qpb.h"#include"fpm/fpm.pb-c.h"/**fpm__route_key__create*/#definefp
m_route_key_createfpm__route_key__createstaticinlineFpm__RouteKey*fpm__route_key
__create(qpb_allocator_t*allocator,structprefix*prefix){Fpm__RouteKey*key;key=QP
B_ALLOC(allocator,typeof(*key));if(!key){returnNULL;}fpm__route_key__init(key);k
ey->prefix=qpb__l3_prefix__create(allocator,prefix);if(!key->prefix){returnNULL;
}returnkey;}#endif