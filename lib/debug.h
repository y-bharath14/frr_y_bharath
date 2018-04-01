/**Debuggingutilities.*Copyright(C)2018CumulusNetworks,Inc.*QuentinYoung**Thispr
ogramisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGene
ralPublicLicenseaspublishedbytheFree*SoftwareFoundation;eitherversion2oftheLicen
se,or(atyouroption)*anylaterversion.**Thisprogramisdistributedinthehopethatitwil
lbeuseful,butWITHOUT*ANYWARRANTY;withouteventheimpliedwarrantyofMERCHANTABILITYo
r*FITNESSFORAPARTICULARPURPOSE.SeetheGNUGeneralPublicLicensefor*moredetails.**Yo
ushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethe
fileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor
,Boston,MA02110-1301USA*/#ifndef_FRRDEBUG_H#define_FRRDEBUG_H#include<zebra.h>#i
nclude"command.h"#include"frratomic.h"/**Debuggingmodes.**FRR'sconventionisthata
debugstatementissuedunderthevtyCONFIG_NODE*persiststotheconfigfile,whereasthesam
edebugstatementissuedfrom*theENABLE_NODEonlypersistsforthecurrentsession.Thesear
emappedto*DEBUG_MODE_CONFandDEBUG_MODE_TERMrespectively.**Theyarenotmutuallyexcl
usiveandareplacedintheMSBoftheflags*fieldinadebuggingrecord.*/#defineDEBUG_MODE_
TERM0x01000000#defineDEBUG_MODE_CONF0x02000000#defineDEBUG_MODE_ALL(DEBUG_MODE_T
ERM|DEBUG_MODE_CONF)#defineDEBUG_MODE_NONE0x00000000#defineDEBUG_OPT_ALL0x00FFFF
FF#defineDEBUG_OPT_NONE0x00000000/**Debuggingrecord.**Alloperationsonthisrecorde
xposedinthisheaderareMT-safe.**flags*Abitfieldwiththefollowingformat(byteshighto
low)*-[0]Debuggingmodefield(MSB)|Mode*-[1]Arbitraryflagfield|Option*-[2]Arbitrar
yflagfield|Option*-[3]Arbitraryflagfield(LSB)|Option**ALLTHESEBYTESAREYOURS-EXCE
PTMODE.*ATTEMPTNOBITOPSTHERE.**TheMSBofthisfielddeterminesthedebugmode,UsetheDEB
UG_MODE**macrostomanipulatethisbyte.**Thelow3bytesofthisfieldmaybeusedtostorearb
itraryinformation.*Usuallytheyareusedtostoreflagsthattunehowdetailedthelogging*f
oraparticulardebugrecordis.UsetheDEBUG_OPT*macrostomanipulate*thosebytes.**Allop
erationsperformedonthisfieldshouldbedoneusingthemacros*laterinthisheaderfile.The
yareguaranteedtobeatomicoperations*withrespecttothisfield.Usinganythingexceptthe
macrosto*manipulatetheflagsfieldinamultithreadedenvironmentresultsin*undefinedbe
havior.**desc*Human-readabledescriptionofthisdebuggingrecord.*/structdebug{_Atom
icuint32_tflags;constchar*desc;};/**Callbacksetfordebuggingcode.**debug_set_all*
Functionpointertocallwhentheuserrequeststhatalldebugshavea*modeset.*/structdebug
_callbacks{/**flags*flagstosetondebugflagfields**set*true:setflags*false:unsetfl
ags*/void(*debug_set_all)(uint32_tflags,boolset);};/**Checkifamodeissetforadebug
.**MT-Safe*/#defineDEBUG_MODE_CHECK(name,mode)\CHECK_FLAG_ATOMIC(&(name)->flags,
(mode)&DEBUG_MODE_ALL)/**Checkifanoptionbitissetforadebug.**MT-Safe*/#defineDEBU
G_OPT_CHECK(name,opt)\CHECK_FLAG_ATOMIC(&(name)->flags,(opt)&DEBUG_OPT_ALL)/**Ch
eckifbitsaresetforadebug.**MT-Safe*/#defineDEBUG_FLAGS_CHECK(name,fl)CHECK_FLAG_
ATOMIC(&(name)->flags,(fl))/**Setmodesonadebug.**MT-Safe*/#defineDEBUG_MODE_SET(
name,mode,onoff)\do{\if(onoff)\SET_FLAG_ATOMIC(&(name)->flags,\(mode)&DEBUG_MODE
_ALL);\else\UNSET_FLAG_ATOMIC(&(name)->flags,\(mode)&DEBUG_MODE_ALL);\}while(0)/
*Conveniencemacrosforspecificsetoperations.*/#defineDEBUG_MODE_ON(name,mode)DEBU
G_MODE_SET(name,mode,true)#defineDEBUG_MODE_OFF(name,mode)DEBUG_MODE_SET(name,mo
de,false)/**Setoptionsonadebug.**MT-Safe*/#defineDEBUG_OPT_SET(name,opt,onoff)\d
o{\if(onoff)\SET_FLAG_ATOMIC(&(name)->flags,(opt)&DEBUG_OPT_ALL);\else\UNSET_FLA
G_ATOMIC(&(name)->flags,\(opt)&DEBUG_OPT_ALL);\}while(0)/*Conveniencemacrosforsp
ecificsetoperations.*/#defineDEBUG_OPT_ON(name,opt)DEBUG_OPT_SET(name,opt,true)#
defineDEBUG_OPT_OFF(name,opt)DEBUG_OPT_SET(name,opt,true)/**Setbitsonadebug.**MT
-Safe*/#defineDEBUG_FLAGS_SET(name,fl,onoff)\do{\if(onoff)\SET_FLAG_ATOMIC(&(nam
e)->flags,(fl));\else\UNSET_FLAG_ATOMIC(&(name)->flags,(fl));\}while(0)/*Conveni
encemacrosforspecificsetoperations.*/#defineDEBUG_FLAGS_ON(name,fl)DEBUG_FLAGS_S
ET(&(name)->flags,(type),true)#defineDEBUG_FLAGS_OFF(name,fl)DEBUG_FLAGS_SET(&(n
ame)->flags,(type),false)/**Unsetallmodesandoptionsonadebug.**MT-Safe*/#defineDE
BUG_CLEAR(name)RESET_FLAG_ATOMIC(&(name)->flags)/**Setallmodesandoptionsonadebug
.**MT-Safe*/#defineDEBUG_ON(name)\SET_FLAG_ATOMIC(&(name)->flags,DEBUG_MODE_ALL|
DEBUG_OPT_ALL)/**Mapavtynodetothecorrectdebuggingmodeflags.FRRbehavessuchthata*d
ebugstatementissuedundertheconfignodepersiststotheconfigfile,*whereasthesamedebu
gstatementissuedfromtheenablenodeonlypersists*forthecurrentsession.**MT-Safe*/#d
efineDEBUG_NODE2MODE(vtynode)\(((vtynode)==CONFIG_NODE)?DEBUG_MODE_ALL:DEBUG_MOD
E_TERM)/**Debugatthegivenleveltothedefaultloggingdestination.**MT-Safe*/#defineD
EBUG(level,name,fmt,...)\do{\if(DEBUG_MODE_CHECK(name,DEBUG_MODE_ALL))\zlog_##le
vel(fmt,##__VA_ARGS__);\}while(0)/*Conveniencemacrosforthevariouslevels.*/#defin
eDEBUGE(name,fmt,...)DEBUG(err,name,fmt,##__VA_ARGS__)#defineDEBUGW(name,fmt,...
)DEBUG(warn,name,fmt,##__VA_ARGS__)#defineDEBUGI(name,fmt,...)DEBUG(info,name,fm
t,##__VA_ARGS__)#defineDEBUGN(name,fmt,...)DEBUG(notice,name,fmt,##__VA_ARGS__)#
defineDEBUGD(name,fmt,...)DEBUG(debug,name,fmt,##__VA_ARGS__)/**Optionalinitiali
zerfordebugging.Highlyrecommended.**Thisfunctioninstallscommondebuggingcommandsa
ndallowsthecallerto*specifycallbackstotakewhenthesecommandsareissued,allowingthe
*callertorespondtoeventssuchasarequesttoturnoffalldebugs.**MT-Safe*/voiddebug_in
it(conststructdebug_callbacks*cb);#endif/*_FRRDEBUG_H*/