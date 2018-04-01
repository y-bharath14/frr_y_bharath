/**Simplestringbuffer**Copyright(C)2017ChristianFranke**ThisfileispartofFRR.**FR
Risfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGeneralP
ublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(atyouropti
on)any*laterversion.**FRRisdistributedinthehopethatitwillbeuseful,but*WITHOUTANY
WARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARP
URPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavereceivedacopy
oftheGNUGeneralPublicLicense*alongwithFRR;seethefileCOPYING.Ifnot,writetotheFree
*SoftwareFoundation,Inc.,59TemplePlace-Suite330,Boston,MA*02111-1307,USA.*/#ifnd
efSBUF_H#defineSBUF_H/**sbufprovidesasimplestringbuffer.Oneapplicationwherethisc
omes*inhandyistheparsingofbinarydata:Ifthereisanerrorintheparsing*processduetoin
validinputdata,printinganerrormessageexplainingwhat*wentwrongisdefinitelyuseful.
However,justprintingtheactualerror,*withoutanyinformationaboutthepreviousparsing
steps,isusuallynotvery*helpful.*Usingsbuf,theparsercanlogthewholeparsingprocessi
ntoabufferusing*aprintflikeAPI.Whenanerrorocurrs,alltheinformationaboutprevious*
parsingstepsisthereinthelog,withoutanyneedforbacktracking,andcan*beusedtogiveade
tailedandusefulerrordescription.*Whenparsingcompletessuccessfullywithoutanyerror
,thelogcanjustbe*discardedunlessdebuggingisturnedon,tonotspamthelog.**Forthedesc
ribedusecase,thecodewouldlooksomethinglikethis:**intsbuf_example(...,char**parse
r_log)*{*structsbuflogbuf;**sbuf_init(&logbuf,NULL,0);*sbuf_push(&logbuf,0,"Star
tingparser\n");**intrv=do_parse(&logbuf,...);***parser_log=sbuf_buf(&logbuf);**r
eturn1;*}**Inthiscase,sbuf_exampleusesastringbufferwithundefinedsize,which*will*
beallocatedontheheapbysbuf.Thecallerofsbuf_exampleisexpectedto*free*thestringret
urnedinparser_log.*/structsbuf{boolfixed;char*buf;size_tsize;size_tpos;intindent
;};voidsbuf_init(structsbuf*dest,char*buf,size_tsize);voidsbuf_reset(structsbuf*
buf);constchar*sbuf_buf(structsbuf*buf);voidsbuf_free(structsbuf*buf);#include"l
ib/log.h"voidsbuf_push(structsbuf*buf,intindent,constchar*format,...)PRINTF_ATTR
IBUTE(3,4);#endif