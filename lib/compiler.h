/**Copyright(c)2015-2017DavidLamparter,forNetDEF,Inc.**Permissiontouse,copy,modi
fy,anddistributethissoftwareforany*purposewithorwithoutfeeisherebygranted,provid
edthattheabove*copyrightnoticeandthispermissionnoticeappearinallcopies.**THESOFT
WAREISPROVIDED"ASIS"ANDTHEAUTHORDISCLAIMSALLWARRANTIES*WITHREGARDTOTHISSOFTWAREI
NCLUDINGALLIMPLIEDWARRANTIESOF*MERCHANTABILITYANDFITNESS.INNOEVENTSHALLTHEAUTHOR
BELIABLEFOR*ANYSPECIAL,DIRECT,INDIRECT,ORCONSEQUENTIALDAMAGESORANYDAMAGES*WHATSO
EVERRESULTINGFROMLOSSOFUSE,DATAORPROFITS,WHETHERINAN*ACTIONOFCONTRACT,NEGLIGENCE
OROTHERTORTIOUSACTION,ARISINGOUTOF*ORINCONNECTIONWITHTHEUSEORPERFORMANCEOFTHISSO
FTWARE.*/#ifndef_FRR_COMPILER_H#define_FRR_COMPILER_H/*functionattributes,uselik
e*voidprototype(void)__attribute__((_CONSTRUCTOR(100)));*/#ifdefined(__clang__)#
if__clang_major__>3||(__clang_major__==3&&__clang_minor__>=5)#define_RET_NONNULL
,returns_nonnull#endif#define_CONSTRUCTOR(x)constructor(x)#elifdefined(__GNUC__)
#if__GNUC__>4||(__GNUC__==4&&__GNUC_MINOR__>=9)#define_RET_NONNULL,returns_nonnu
ll#endif#if__GNUC__>4||(__GNUC__==4&&__GNUC_MINOR__>=3)#define_CONSTRUCTOR(x)con
structor(x)#define_DESTRUCTOR(x)destructor(x)#define_ALLOC_SIZE(x)alloc_size(x)#
endif#endif#ifdef__sun/*Solarisdoesn'tdoconstructorprioritiesduetolinkerrestrict
ions*/#undef_CONSTRUCTOR#undef_DESTRUCTOR#endif/*fallbackversions*/#ifndef_RET_N
ONNULL#define_RET_NONNULL#endif#ifndef_CONSTRUCTOR#define_CONSTRUCTOR(x)construc
tor#endif#ifndef_DESTRUCTOR#define_DESTRUCTOR(x)destructor#endif#ifndef_ALLOC_SI
ZE#define_ALLOC_SIZE(x)#endif/**forwarningsonmacros,putinthemacrocontentlikethis
:*#defineMACROBLACPP_WARN("MACROhasbeendeprecated")*/#defineCPP_STR(X)#X#ifdefin
ed(__ICC)#defineCPP_NOTICE(text)_Pragma(CPP_STR(message__FILE__":"text))#defineC
PP_WARN(text)CPP_NOTICE(text)#elif(defined(__GNUC__)\&&(__GNUC__>=5||(__GNUC__==
4&&__GNUC_MINOR__>=8)))\||(defined(__clang__)\&&(__clang_major__>=4\||(__clang_m
ajor__==3&&__clang_minor__>=5)))#defineCPP_WARN(text)_Pragma(CPP_STR(GCCwarningt
ext))#defineCPP_NOTICE(text)_Pragma(CPP_STR(messagetext))#else#defineCPP_WARN(te
xt)#endif#endif/*_FRR_COMPILER_H*/