/**Copyright(c)2015-16DavidLamparter,forNetDEF,Inc.**Permissionisherebygranted,f
reeofcharge,toanypersonobtaininga*copyofthissoftwareandassociateddocumentationfi
les(the"Software"),*todealintheSoftwarewithoutrestriction,includingwithoutlimita
tion*therightstouse,copy,modify,merge,publish,distribute,sublicense,*and/orsellc
opiesoftheSoftware,andtopermitpersonstowhomthe*Softwareisfurnishedtodoso,subject
tothefollowingconditions:**Theabovecopyrightnoticeandthispermissionnoticeshallbe
includedin*allcopiesorsubstantialportionsoftheSoftware.**THESOFTWAREISPROVIDED"A
SIS",WITHOUTWARRANTYOFANYKIND,EXPRESSOR*IMPLIED,INCLUDINGBUTNOTLIMITEDTOTHEWARRA
NTIESOFMERCHANTABILITY,*FITNESSFORAPARTICULARPURPOSEANDNONINFRINGEMENT.INNOEVENT
SHALL*THEAUTHORSORCOPYRIGHTHOLDERSBELIABLEFORANYCLAIM,DAMAGESOROTHER*LIABILITY,W
HETHERINANACTIONOFCONTRACT,TORTOROTHERWISE,ARISING*FROM,OUTOFORINCONNECTIONWITHT
HESOFTWAREORTHEUSEOROTHER*DEALINGSINTHESOFTWARE.*/#include"config.h"#include<std
lib.h>#include<stdio.h>#include<string.h>#include<unistd.h>#include<limits.h>#in
clude<dlfcn.h>#include"module.h"#include"memory.h"#include"version.h"DEFINE_MTYP
E_STATIC(LIB,MODULE_LOADNAME,"Moduleloadingname")DEFINE_MTYPE_STATIC(LIB,MODULE_
LOADARGS,"Moduleloadingarguments")staticstructfrrmod_infofrrmod_default_info={.n
ame="libfrr",.version=FRR_VERSION,.description="libfrrcoremodule",};union_frrmod
_runtime_ufrrmod_default={.r={.info=&frrmod_default_info,.finished_loading=1,},}
;//ifdefined(HAVE_SYS_WEAK_ALIAS_ATTRIBUTE)//union_frrmod_runtime_u_frrmod_this_
module//__attribute__((weak,alias("frrmod_default")));//elifdefined(HAVE_SYS_WEA
K_ALIAS_PRAGMA)#pragmaweak_frrmod_this_module=frrmod_default//else//errorneedwea
ksymbolsupport//endifstructfrrmod_runtime*frrmod_list=&frrmod_default.r;staticst
ructfrrmod_runtime**frrmod_last=&frrmod_default.r.next;staticconstchar*execname=
NULL;voidfrrmod_init(structfrrmod_runtime*modinfo){modinfo->finished_loading=1;*
frrmod_last=modinfo;frrmod_last=&modinfo->next;execname=modinfo->info->name;}str
uctfrrmod_runtime*frrmod_load(constchar*spec,constchar*dir,char*err,size_terr_le
n){void*handle=NULL;charname[PATH_MAX],fullpath[PATH_MAX],*args;structfrrmod_run
time*rtinfo,**rtinfop;conststructfrrmod_info*info;snprintf(name,sizeof(name),"%s
",spec);args=strchr(name,':');if(args)*args++='\0';if(!strchr(name,'/')){if(!han
dle&&execname){snprintf(fullpath,sizeof(fullpath),"%s/%s_%s.so",dir,execname,nam
e);handle=dlopen(fullpath,RTLD_NOW|RTLD_GLOBAL);}if(!handle){snprintf(fullpath,s
izeof(fullpath),"%s/%s.so",dir,name);handle=dlopen(fullpath,RTLD_NOW|RTLD_GLOBAL
);}}if(!handle){snprintf(fullpath,sizeof(fullpath),"%s",name);handle=dlopen(full
path,RTLD_NOW|RTLD_GLOBAL);}if(!handle){if(err)snprintf(err,err_len,"loadingmodu
le\"%s\"failed:%s",name,dlerror());returnNULL;}rtinfop=dlsym(handle,"frr_module"
);if(!rtinfop){dlclose(handle);if(err)snprintf(err,err_len,"\"%s\"isnotanFRRmodu
le:%s",name,dlerror());returnNULL;}rtinfo=*rtinfop;rtinfo->load_name=XSTRDUP(MTY
PE_MODULE_LOADNAME,name);rtinfo->dl_handle=handle;if(args)rtinfo->load_args=XSTR
DUP(MTYPE_MODULE_LOADARGS,args);info=rtinfo->info;if(rtinfo->finished_loading){d
lclose(handle);if(err)snprintf(err,err_len,"module\"%s\"alreadyloaded",name);got
oout_fail;}if(info->init&&info->init()){dlclose(handle);if(err)snprintf(err,err_
len,"module\"%s\"initialisationfailed",name);gotoout_fail;}rtinfo->finished_load
ing=1;*frrmod_last=rtinfo;frrmod_last=&rtinfo->next;returnrtinfo;out_fail:if(rti
nfo->load_args)XFREE(MTYPE_MODULE_LOADARGS,rtinfo->load_args);XFREE(MTYPE_MODULE
_LOADNAME,rtinfo->load_name);returnNULL;}#if0voidfrrmod_unload(structfrrmod_runt
ime*module){}#endif