/**Copyright(c)2015-16DavidLamparter,forNetDEF,Inc.**Permissiontouse,copy,modify
,anddistributethissoftwareforany*purposewithorwithoutfeeisherebygranted,provided
thattheabove*copyrightnoticeandthispermissionnoticeappearinallcopies.**THESOFTWA
REISPROVIDED"ASIS"ANDTHEAUTHORDISCLAIMSALLWARRANTIES*WITHREGARDTOTHISSOFTWAREINC
LUDINGALLIMPLIEDWARRANTIESOF*MERCHANTABILITYANDFITNESS.INNOEVENTSHALLTHEAUTHORBE
LIABLEFOR*ANYSPECIAL,DIRECT,INDIRECT,ORCONSEQUENTIALDAMAGESORANYDAMAGES*WHATSOEV
ERRESULTINGFROMLOSSOFUSE,DATAORPROFITS,WHETHERINAN*ACTIONOFCONTRACT,NEGLIGENCEOR
OTHERTORTIOUSACTION,ARISINGOUTOF*ORINCONNECTIONWITHTHEUSEORPERFORMANCEOFTHISSOFT
WARE.*/#ifndef_FRRATOMIC_H#define_FRRATOMIC_H#ifdefHAVE_CONFIG_H#include"config.
h"#endif#ifndefFRR_AUTOCONF_ATOMIC#errorautoconfchecksforatomicfunctionswerenotp
roperlyrun#endif/*ISOC11*/#ifdefHAVE_STDATOMIC_H#include<stdatomic.h>/*gcc4.7and
newer*/#elifdefined(HAVE___ATOMIC)#define_Atomicvolatile#definememory_order_rela
xed__ATOMIC_RELAXED#definememory_order_consume__ATOMIC_CONSUME#definememory_orde
r_acquire__ATOMIC_ACQUIRE#definememory_order_release__ATOMIC_RELEASE#definememor
y_order_acq_rel__ATOMIC_ACQ_REL#definememory_order_seq_cst__ATOMIC_SEQ_CST#defin
eatomic_load_explicit__atomic_load_n#defineatomic_store_explicit__atomic_store_n
#defineatomic_exchange_explicit__atomic_exchange_n#defineatomic_fetch_add_explic
it__atomic_fetch_add#defineatomic_fetch_sub_explicit__atomic_fetch_sub#defineato
mic_fetch_and_explicit__atomic_fetch_and#defineatomic_fetch_or_explicit__atomic_
fetch_or#defineatomic_compare_exchange_weak_explicit(atom,expect,desire,mem1,\me
m2)\__atomic_compare_exchange_n(atom,expect,desire,1,mem1,mem2)/*gcc4.1andnewer,
*clang3.3(possiblyolder)**__sync_swapisn'tingcc'sdocumentation,butclanghasit**no
te__sync_synchronize()*/#elifdefined(HAVE___SYNC)#define_Atomicvolatile#defineme
mory_order_relaxed0#definememory_order_consume0#definememory_order_acquire0#defi
nememory_order_release0#definememory_order_acq_rel0#definememory_order_seq_cst0#
defineatomic_load_explicit(ptr,mem)\({\__sync_synchronize();\typeof(*ptr)rval=__
sync_fetch_and_add((ptr),0);\__sync_synchronize();\rval;\})#defineatomic_store_e
xplicit(ptr,val,mem)\({\__sync_synchronize();\*(ptr)=(val);\__sync_synchronize()
;\(void)0;\})#ifdefHAVE___SYNC_SWAP#defineatomic_exchange_explicit(ptr,val,mem)\
({\__sync_synchronize();\typeof(*ptr)rval=__sync_swap((ptr,val),0);\__sync_synch
ronize();\rval;\})#else/*!HAVE___SYNC_SWAP*/#defineatomic_exchange_explicit(ptr,
val,mem)\({\typeof(ptr)_ptr=(ptr);\typeof(val)_val=(val);\__sync_synchronize();\
typeof(*ptr)old1,old2=__sync_fetch_and_add(_ptr,0);\do{\old1=old2;\old2=__sync_v
al_compare_and_swap(_ptr,old1,_val);\}while(old1!=old2);\__sync_synchronize();\o
ld2;\})#endif/*!HAVE___SYNC_SWAP*/#defineatomic_fetch_add_explicit(ptr,val,mem)\
({\__sync_synchronize();\typeof(*ptr)rval=__sync_fetch_and_add((ptr),(val));\__s
ync_synchronize();\rval;\})#defineatomic_fetch_sub_explicit(ptr,val,mem)\({\__sy
nc_synchronize();\typeof(*ptr)rval=__sync_fetch_and_sub((ptr),(val));\__sync_syn
chronize();\rval;\})#defineatomic_compare_exchange_weak_explicit(atom,expect,des
ire,mem1,\mem2)\({\typeof(atom)_atom=(atom);\typeof(expect)_expect=(expect);\typ
eof(desire)_desire=(desire);\__sync_synchronize();\typeof(*atom)rval=\__sync_val
_compare_and_swap(_atom,*_expect,_desire);\__sync_synchronize();\boolret=(rval==
*_expect);\*_expect=rval;\ret;\})#defineatomic_fetch_and_explicit(ptr,val,mem)\(
{\__sync_synchronize();\typeof(*ptr)rval=__sync_fetch_and_and(ptr,val);\__sync_s
ynchronize();\rval;\})#defineatomic_fetch_or_explicit(ptr,val,mem)\({\__sync_syn
chronize();\typeof(*ptr)rval=__sync_fetch_and_or(ptr,val);\__sync_synchronize();
\rval;\})#else/*!HAVE___ATOMIC&&!HAVE_STDATOMIC_H*/#errornoatomicfunctions...#en
dif#endif/*_FRRATOMIC_H*/