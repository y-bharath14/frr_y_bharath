/*Copyright(c)2007,2008byJuliuszChroboczekPermissionisherebygranted,freeofcharge
,toanypersonobtainingacopyofthissoftwareandassociateddocumentationfiles(the"Soft
ware"),todealintheSoftwarewithoutrestriction,includingwithoutlimitationtherights
touse,copy,modify,merge,publish,distribute,sublicense,and/orsellcopiesoftheSoftw
are,andtopermitpersonstowhomtheSoftwareisfurnishedtodoso,subjecttothefollowingco
nditions:Theabovecopyrightnoticeandthispermissionnoticeshallbeincludedinallcopie
sorsubstantialportionsoftheSoftware.THESOFTWAREISPROVIDED"ASIS",WITHOUTWARRANTYO
FANYKIND,EXPRESSORIMPLIED,INCLUDINGBUTNOTLIMITEDTOTHEWARRANTIESOFMERCHANTABILITY
,FITNESSFORAPARTICULARPURPOSEANDNONINFRINGEMENT.INNOEVENTSHALLTHEAUTHORSORCOPYRI
GHTHOLDERSBELIABLEFORANYCLAIM,DAMAGESOROTHERLIABILITY,WHETHERINANACTIONOFCONTRAC
T,TORTOROTHERWISE,ARISINGFROM,OUTOFORINCONNECTIONWITHTHESOFTWAREORTHEUSEOROTHERD
EALINGSINTHESOFTWARE.*/#ifndefBABEL_KERNEL_H#defineBABEL_KERNEL_H#include<netine
t/in.h>#include"babel_main.h"#include"if.h"#defineKERNEL_INFINITY0xFFFF#defineRO
UTE_FLUSH0#defineROUTE_ADD1#defineROUTE_MODIFY2intkernel_interface_operational(s
tructinterface*interface);intkernel_interface_mtu(structinterface*interface);int
kernel_interface_wireless(structinterface*interface);intkernel_route(intoperatio
n,constunsignedchar*dest,unsignedshortplen,constunsignedchar*gate,intifindex,uns
ignedintmetric,constunsignedchar*newgate,intnewifindex,unsignedintnewmetric);int
if_eui64(intifindex,unsignedchar*eui);intgettime(structtimeval*tv);intread_rando
m_bytes(void*buf,size_tlen);#endif/*BABEL_KERNEL_H*/