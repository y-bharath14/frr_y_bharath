/**Interfacelookingupbyioctl()onSolaris.*Copyright(C)1999KunihiroIshiguro**Thisf
ileispartofQuagga.**Quaggaisfreesoftware;youcanredistributeitand/ormodifyit*unde
rthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eit
herversion2,or(atyouroption)any*laterversion.**Quaggaisdistributedinthehopethati
twillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABI
LITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.
**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;se
ethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthF
loor,Boston,MA02110-1301USA*/#ifndef_ZEBRA_IF_IOCTL_SOLARIS_H#define_ZEBRA_IF_IO
CTL_SOLARIS_Hvoidlifreq_set_name(structlifreq*,constchar*);intif_get_flags_direc
t(constchar*,uint64_t*,unsignedintaf);#endif/*_ZEBRA_IF_IOCTL_SOLARIS_H*/