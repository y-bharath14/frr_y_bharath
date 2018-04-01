/**Copyright(C)2016byOpenSourceRouting.**Thisprogramisfreesoftware;youcanredistr
ibuteitand/ormodify*itunderthetermsoftheGNUGeneralPublicLicenseaspublishedby*the
FreeSoftwareFoundation;eitherversion2oftheLicense,or*(atyouroption)anylaterversi
on.**Thisprogramisdistributedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;
withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.Se
etheGNU*GeneralPublicLicenseformoredetails.**YoushouldhavereceivedacopyoftheGNUG
eneralPublicLicense*alongwiththisprogram;seethefileCOPYING;ifnot,writetothe*Free
SoftwareFoundation,Inc.,51FranklinSt,FifthFloor,Boston,*MA02110-1301USA*/#includ
e<zebra.h>#include"command.h"#include"vty.h"#include"json.h"#include"ldpd/ldpd.h
"#include"ldpd/ldp_vty.h"#ifndefVTYSH_EXTRACT_PL#include"ldpd/ldp_vty_cmds_clipp
y.c"#endifDEFUN_NOSH(ldp_mpls_ldp,ldp_mpls_ldp_cmd,"mplsldp","GlobalMPLSconfigur
ationsubcommands\n""LabelDistributionProtocol\n"){return(ldp_vty_mpls_ldp(vty,NU
LL));}DEFPY(no_ldp_mpls_ldp,no_ldp_mpls_ldp_cmd,"nomplsldp",NO_STR"GlobalMPLScon
figurationsubcommands\n""LabelDistributionProtocol\n"){return(ldp_vty_mpls_ldp(v
ty,"no"));}DEFUN_NOSH(ldp_l2vpn,ldp_l2vpn_cmd,"l2vpnWORDtypevpls","Configurel2vp
ncommands\n""L2VPNname\n""L2VPNtype\n""VirtualPrivateLANService\n"){intidx=0;con
stchar*name;argv_find(argv,argc,"WORD",&idx);name=argv[idx]->arg;return(ldp_vty_
l2vpn(vty,0,name));}DEFPY(no_ldp_l2vpn,no_ldp_l2vpn_cmd,"nol2vpnWORD$l2vpn_namet
ypevpls",NO_STR"Configurel2vpncommands\n""L2VPNname\n""L2VPNtype\n""VirtualPriva
teLANService\n"){return(ldp_vty_l2vpn(vty,"no",l2vpn_name));}DEFUN_NOSH(ldp_addr
ess_family,ldp_address_family_cmd,"address-family<ipv4|ipv6>","ConfigureAddressF
amilyanditsparameters\n""IPv4\n""IPv6\n"){intidx=0;constchar*af;argv_find(argv,a
rgc,"address-family",&idx);af=argv[idx+1]->text;return(ldp_vty_address_family(vt
y,0,af));}DEFPY(no_ldp_address_family,no_ldp_address_family_cmd,"noaddress-famil
y<ipv4|ipv6>$af",NO_STR"ConfigureAddressFamilyanditsparameters\n""IPv4\n""IPv6\n
"){return(ldp_vty_address_family(vty,"no",af));}DEFUN_NOSH(ldp_exit_address_fami
ly,ldp_exit_address_family_cmd,"exit-address-family","ExitfromAddressFamilyconfi
gurationmode\n"){if(vty->node==LDP_IPV4_NODE||vty->node==LDP_IPV6_NODE)vty->node
=LDP_NODE;returnCMD_SUCCESS;}DEFPY(ldp_discovery_link_holdtime,ldp_discovery_lin
k_holdtime_cmd,"[no]discoveryhelloholdtime(1-65535)$holdtime",NO_STR"Configuredi
scoveryparameters\n""LDPLinkHellos\n""Helloholdtime\n""Time(seconds)-65535implie
sinfinite\n"){return(ldp_vty_disc_holdtime(vty,no,HELLO_LINK,holdtime));}DEFPY(l
dp_discovery_targeted_holdtime,ldp_discovery_targeted_holdtime_cmd,"[no]discover
ytargeted-helloholdtime(1-65535)$holdtime",NO_STR"Configurediscoveryparameters\n
""LDPTargetedHellos\n""Helloholdtime\n""Time(seconds)-65535impliesinfinite\n"){r
eturn(ldp_vty_disc_holdtime(vty,no,HELLO_TARGETED,holdtime));}DEFPY(ldp_discover
y_link_interval,ldp_discovery_link_interval_cmd,"[no]discoveryhellointerval(1-65
535)$interval",NO_STR"Configurediscoveryparameters\n""LDPLinkHellos\n""Hellointe
rval\n""Time(seconds)\n"){return(ldp_vty_disc_interval(vty,no,HELLO_LINK,interva
l));}DEFPY(ldp_discovery_targeted_interval,ldp_discovery_targeted_interval_cmd,"
[no]discoverytargeted-hellointerval(1-65535)$interval",NO_STR"Configurediscovery
parameters\n""LDPTargetedHellos\n""Hellointerval\n""Time(seconds)\n"){return(ldp
_vty_disc_interval(vty,no,HELLO_TARGETED,interval));}DEFPY(ldp_dual_stack_transp
ort_connection_prefer_ipv4,ldp_dual_stack_transport_connection_prefer_ipv4_cmd,"
[no]dual-stacktransport-connectionpreferipv4",NO_STR"Configuredualstackparameter
s\n""ConfigureTCPtransportparameters\n""ConfigurepreferedaddressfamilyforTCPtran
sportconnectionwithneighbor\n""IPv4\n"){return(ldp_vty_trans_pref_ipv4(vty,no));
}DEFPY(ldp_dual_stack_cisco_interop,ldp_dual_stack_cisco_interop_cmd,"[no]dual-s
tackcisco-interop",NO_STR"Configuredualstackparameters\n""UseCisconon-compliantf
ormattosendandinterprettheDual-StackcapabilityTLV\n"){return(ldp_vty_ds_cisco_in
terop(vty,no));}DEFPY(ldp_neighbor_password,ldp_neighbor_password_cmd,"[no]neigh
borA.B.C.D$neighborpasswordWORD$password",NO_STR"Configureneighborparameters\n""
LDPIdofneighbor\n""ConfigurepasswordforMD5authentication\n""Thepassword\n"){retu
rn(ldp_vty_neighbor_password(vty,no,neighbor,password));}DEFPY(ldp_neighbor_sess
ion_holdtime,ldp_neighbor_session_holdtime_cmd,"[no]neighborA.B.C.D$neighborsess
ionholdtime(15-65535)$holdtime",NO_STR"Configureneighborparameters\n""LDPIdofnei
ghbor\n""Configuresessionparameters\n""Configuresessionholdtime\n""Time(seconds)
\n"){return(ldp_vty_nbr_session_holdtime(vty,no,neighbor,holdtime));}DEFPY(ldp_n
eighbor_ttl_security,ldp_neighbor_ttl_security_cmd,"[no]neighborA.B.C.D$neighbor
ttl-security<disable|hops(1-254)$hops>",NO_STR"Configureneighborparameters\n""LD
PIdofneighbor\n""LDPttlsecuritycheck\n""Disablettlsecurity\n""IPhops\n""maximumn
umberofhops\n"){return(ldp_vty_neighbor_ttl_security(vty,no,neighbor,hops_str));
}DEFPY(ldp_router_id,ldp_router_id_cmd,"[no]router-idA.B.C.D$address",NO_STR"Con
figurerouterId\n""LSRId(informofanIPv4address)\n"){return(ldp_vty_router_id(vty,
no,address));}DEFPY(ldp_discovery_targeted_hello_accept,ldp_discovery_targeted_h
ello_accept_cmd,"[no]discoverytargeted-helloaccept[from<(1-199)|(1300-2699)|WORD
>$from_acl]",NO_STR"Configurediscoveryparameters\n""LDPTargetedHellos\n""Accepta
ndrespondtotargetedhellos\n""Accesslisttospecifyacceptabletargetedhellosource\n"
"IPaccess-listnumber\n""IPaccess-listnumber(expandedrange)\n""IPaccess-listname\
n"){return(ldp_vty_targeted_hello_accept(vty,no,from_acl));}DEFPY(ldp_discovery_
transport_address_ipv4,ldp_discovery_transport_address_ipv4_cmd,"[no]discoverytr
ansport-addressA.B.C.D$address",NO_STR"Configurediscoveryparameters\n""Specifytr
ansportaddressforTCPconnection\n""IPaddresstobeusedastransportaddress\n"){return
(ldp_vty_trans_addr(vty,no,address_str));}DEFPY(ldp_discovery_transport_address_
ipv6,ldp_discovery_transport_address_ipv6_cmd,"[no]discoverytransport-addressX:X
::X:X$address",NO_STR"Configurediscoveryparameters\n""Specifytransportaddressfor
TCPconnection\n""IPv6addresstobeusedastransportaddress\n"){return(ldp_vty_trans_
addr(vty,no,address_str));}DEFPY(ldp_label_local_advertise,ldp_label_local_adver
tise_cmd,"[no]labellocaladvertise[{to<(1-199)|(1300-2699)|WORD>$to_acl|for<(1-19
9)|(1300-2699)|WORD>$for_acl}]",NO_STR"Configurelabelcontrolandpolicies\n""Confi
gurelocallabelcontrolandpolicies\n""Configureoutboundlabeladvertisementcontrol\n
""IPAccess-listspecifyingcontrolsonLDPPeers\n""IPaccess-listnumber\n""IPaccess-l
istnumber(expandedrange)\n""IPaccess-listname\n""IPaccess-listfordestinationpref
ixes\n""IPaccess-listnumber\n""IPaccess-listnumber(expandedrange)\n""IPaccess-li
stname\n"){return(ldp_vty_label_advertise(vty,no,to_acl,for_acl));}DEFPY(ldp_lab
el_local_advertise_explicit_null,ldp_label_local_advertise_explicit_null_cmd,"[n
o]labellocaladvertiseexplicit-null[for<(1-199)|(1300-2699)|WORD>$for_acl]",NO_ST
R"Configurelabelcontrolandpolicies\n""Configurelocallabelcontrolandpolicies\n""C
onfigureoutboundlabeladvertisementcontrol\n""Configureexplicit-nulladvertisement
\n""IPaccess-listfordestinationprefixes\n""IPaccess-listnumber\n""IPaccess-listn
umber(expandedrange)\n""IPaccess-listname\n"){return(ldp_vty_label_expnull(vty,n
o,for_acl));}DEFPY(ldp_label_local_allocate,ldp_label_local_allocate_cmd,"[no]la
bellocalallocate<host-routes$host_routes|for<(1-199)|(1300-2699)|WORD>$for_acl>"
,NO_STR"Configurelabelcontrolandpolicies\n""Configurelocallabelcontrolandpolicie
s\n""Configurelabelallocationcontrol\n""allocatelocallabelforhostroutesonly\n""I
Paccess-list\n""IPaccess-listnumber\n""IPaccess-listnumber(expandedrange)\n""IPa
ccess-listname\n"){return(ldp_vty_label_allocate(vty,no,host_routes,for_acl));}D
EFPY(ldp_label_remote_accept,ldp_label_remote_accept_cmd,"[no]labelremoteaccept{
from<(1-199)|(1300-2699)|WORD>$from_acl|for<(1-199)|(1300-2699)|WORD>$for_acl}",
NO_STR"Configurelabelcontrolandpolicies\n""Configureremote/peerlabelcontrolandpo
licies\n""Configureinboundlabelacceptancecontrol\n""Neighborfromwhomtoacceptlabe
ladvertisement\n""IPaccess-listnumber\n""IPaccess-listnumber(expandedrange)\n""I
Paccess-listname\n""IPaccess-listfordestinationprefixes\n""IPaccess-listnumber\n
""IPaccess-listnumber(expandedrange)\n""IPaccess-listname\n"){return(ldp_vty_lab
el_accept(vty,no,from_acl,for_acl));}DEFPY(ldp_ttl_security_disable,ldp_ttl_secu
rity_disable_cmd,"[no]ttl-securitydisable",NO_STR"LDPttlsecuritycheck\n""Disable
ttlsecurity\n"){return(ldp_vty_ttl_security(vty,no));}DEFPY(ldp_session_holdtime
,ldp_session_holdtime_cmd,"[no]sessionholdtime(15-65535)$holdtime",NO_STR"Config
uresessionparameters\n""Configuresessionholdtime\n""Time(seconds)\n"){return(ldp
_vty_af_session_holdtime(vty,no,holdtime));}DEFUN_NOSH(ldp_interface,ldp_interfa
ce_cmd,"interfaceIFNAME","EnableLDPonaninterfaceandenterinterfacesubmode\n""Inte
rface'sname\n"){intidx=0;constchar*ifname;argv_find(argv,argc,"IFNAME",&idx);ifn
ame=argv[idx]->arg;return(ldp_vty_interface(vty,0,ifname));}DEFPY(no_ldp_interfa
ce,no_ldp_interface_cmd,"nointerfaceIFNAME$ifname",NO_STR"EnableLDPonaninterface
andenterinterfacesubmode\n""Interface'sname\n"){return(ldp_vty_interface(vty,"no
",ifname));}DEFPY(ldp_neighbor_ipv4_targeted,ldp_neighbor_ipv4_targeted_cmd,"[no
]neighborA.B.C.D$addresstargeted",NO_STR"Configureneighborparameters\n""IPaddres
sofneighbor\n""Establishtargetedsession\n"){return(ldp_vty_neighbor_targeted(vty
,no,address_str));}DEFPY(ldp_neighbor_ipv6_targeted,ldp_neighbor_ipv6_targeted_c
md,"[no]neighborX:X::X:X$addresstargeted",NO_STR"Configureneighborparameters\n""
IPv6addressofneighbor\n""Establishtargetedsession\n"){return(ldp_vty_neighbor_ta
rgeted(vty,no,address_str));}DEFPY(ldp_bridge,ldp_bridge_cmd,"[no]bridgeIFNAME$i
fname",NO_STR"Bridgeinterface\n""Interface'sname\n"){return(ldp_vty_l2vpn_bridge
(vty,no,ifname));}DEFPY(ldp_mtu,ldp_mtu_cmd,"[no]mtu(1500-9180)$mtu",NO_STR"SetM
aximumTransmissionUnit\n""MaximumTransmissionUnitvalue\n"){return(ldp_vty_l2vpn_
mtu(vty,no,mtu));}DEFPY(ldp_member_interface,ldp_member_interface_cmd,"[no]membe
rinterfaceIFNAME$ifname",NO_STR"L2VPNmemberconfiguration\n""Localinterface\n""In
terface'sname\n"){return(ldp_vty_l2vpn_interface(vty,no,ifname));}DEFUN_NOSH(ldp
_member_pseudowire,ldp_member_pseudowire_cmd,"memberpseudowireIFNAME","L2VPNmemb
erconfiguration\n""Pseudowireinterface\n""Interface'sname\n"){intidx=0;constchar
*ifname;argv_find(argv,argc,"IFNAME",&idx);ifname=argv[idx]->arg;return(ldp_vty_
l2vpn_pseudowire(vty,0,ifname));}DEFPY(no_ldp_member_pseudowire,no_ldp_member_ps
eudowire_cmd,"nomemberpseudowireIFNAME$ifname",NO_STR"L2VPNmemberconfiguration\n
""Pseudowireinterface\n""Interface'sname\n"){return(ldp_vty_l2vpn_pseudowire(vty
,"no",ifname));}DEFPY(ldp_vc_type,ldp_vc_type_cmd,"[no]vctype<ethernet|ethernet-
tagged>$vc_type",NO_STR"VirtualCircuitoptions\n""VirtualCircuittypetouse\n""Ethe
rnet(type5)\n""Ethernet-tagged(type4)\n"){return(ldp_vty_l2vpn_pwtype(vty,no,vc_
type));}DEFPY(ldp_control_word,ldp_control_word_cmd,"[no]control-word<exclude|in
clude>$preference",NO_STR"Control-wordoptions\n""Excludecontrol-wordinpseudowire
packets\n""Includecontrol-wordinpseudowirepackets\n"){return(ldp_vty_l2vpn_pw_cw
ord(vty,no,preference));}DEFPY(ldp_neighbor_address,ldp_neighbor_address_cmd,"[n
o]neighboraddress<A.B.C.D|X:X::X:X>$pw_address",NO_STR"Remoteendpointconfigurati
on\n""SpecifytheIPv4orIPv6addressoftheremoteendpoint\n""IPv4address\n""IPv6addre
ss\n"){return(ldp_vty_l2vpn_pw_nbr_addr(vty,no,pw_address_str));}DEFPY(ldp_neigh
bor_lsr_id,ldp_neighbor_lsr_id_cmd,"[no]neighborlsr-idA.B.C.D$address",NO_STR"Re
moteendpointconfiguration\n""SpecifytheLSR-IDoftheremoteendpoint\n""IPv4address\
n"){return(ldp_vty_l2vpn_pw_nbr_id(vty,no,address));}DEFPY(ldp_pw_id,ldp_pw_id_c
md,"[no]pw-id(1-4294967295)$pwid",NO_STR"SettheVirtualCircuitID\n""VirtualCircui
tIDvalue\n"){return(ldp_vty_l2vpn_pw_pwid(vty,no,pwid));}DEFPY(ldp_pw_status_dis
able,ldp_pw_status_disable_cmd,"[no]pw-statusdisable",NO_STR"ConfigurePWstatus\n
""DisablePWstatus\n"){return(ldp_vty_l2vpn_pw_pwstatus(vty,no));}DEFPY(ldp_clear
_mpls_ldp_neighbor,ldp_clear_mpls_ldp_neighbor_cmd,"clearmplsldpneighbor[<A.B.C.
D|X:X::X:X>]$address","Resetfunctions\n""ResetMPLSstatisticalinformation\n""Clea
rLDPstate\n""ClearLDPneighborsessions\n""IPv4address\n""IPv6address\n"){return(l
dp_vty_clear_nbr(vty,address_str));}DEFPY(ldp_debug_mpls_ldp_discovery_hello,ldp
_debug_mpls_ldp_discovery_hello_cmd,"[no]debugmplsldpdiscoveryhello<recv|sent>$d
ir",NO_STR"Debuggingfunctions\n""MPLSinformation\n""LabelDistributionProtocol\n"
"Discoverymessages\n""Discoveryhellomessage\n""Receivedmessages\n""Sentmessages\
n"){return(ldp_vty_debug(vty,no,"discovery",dir,NULL));}DEFPY(ldp_debug_mpls_ldp
_type,ldp_debug_mpls_ldp_type_cmd,"[no]debugmplsldp<errors|event|labels|zebra>$t
ype",NO_STR"Debuggingfunctions\n""MPLSinformation\n""LabelDistributionProtocol\n
""Errors\n""LDPeventinformation\n""LDPlabelallocationinformation\n""LDPzebrainfo
rmation\n"){return(ldp_vty_debug(vty,no,type,NULL,NULL));}DEFPY(ldp_debug_mpls_l
dp_messages_recv,ldp_debug_mpls_ldp_messages_recv_cmd,"[no]debugmplsldpmessagesr
ecv[all]$all",NO_STR"Debuggingfunctions\n""MPLSinformation\n""LabelDistributionP
rotocol\n""Messages\n""Receivedmessages,excludingperiodicKeepAlives\n""Receivedm
essages,includingperiodicKeepAlives\n"){return(ldp_vty_debug(vty,no,"messages","
recv",all));}DEFPY(ldp_debug_mpls_ldp_messages_sent,ldp_debug_mpls_ldp_messages_
sent_cmd,"[no]debugmplsldpmessagessent[all]$all",NO_STR"Debuggingfunctions\n""MP
LSinformation\n""LabelDistributionProtocol\n""Messages\n""Sentmessages,excluding
periodicKeepAlives\n""Sentmessages,includingperiodicKeepAlives\n"){return(ldp_vt
y_debug(vty,no,"messages","sent",all));}DEFPY(ldp_show_mpls_ldp_binding,ldp_show
_mpls_ldp_binding_cmd,"showmplsldp[<ipv4|ipv6>]$afbinding\[<A.B.C.D/M|X:X::X:X/M
>$prefix[longer-prefixes$longer_prefixes]]\[{\neighborA.B.C.D$nbr\|local-label(0
-1048575)$local_label\|remote-label(0-1048575)$remote_label\}]\[detail]$detail[j
son]$json","Showrunningsysteminformation\n""MPLSinformation\n""LabelDistribution
Protocol\n""IPv4AddressFamily\n""IPv6AddressFamily\n""LabelInformationBase(LIB)i
nformation\n""Destinationprefix(IPv4)\n""Destinationprefix(IPv6)\n""Includelonge
rmatches\n""DisplaylabelsfromLDPneighbor\n""NeighborLSR-ID\n""Matchlocallyassign
edlabelvalues\n""Locallyassignedlabelvalue\n""Matchremotelyassignedlabelvalues\n
""Remotelyassignedlabelvalue\n""Showdetailedinformation\n"JSON_STR){if(!local_la
bel_str)local_label=NO_LABEL;if(!remote_label_str)remote_label=NO_LABEL;return(l
dp_vty_show_binding(vty,af,prefix_str,!!longer_prefixes,nbr_str,local_label,remo
te_label,detail,json));}DEFPY(ldp_show_mpls_ldp_discovery,ldp_show_mpls_ldp_disc
overy_cmd,"showmplsldp[<ipv4|ipv6>]$afdiscovery[detail]$detail[json]$json","Show
runningsysteminformation\n""MPLSinformation\n""LabelDistributionProtocol\n""IPv4
AddressFamily\n""IPv6AddressFamily\n""DiscoveryHelloInformation\n""Showdetailedi
nformation\n"JSON_STR){return(ldp_vty_show_discovery(vty,af,detail,json));}DEFPY
(ldp_show_mpls_ldp_interface,ldp_show_mpls_ldp_interface_cmd,"showmplsldp[<ipv4|
ipv6>]$afinterface[json]$json","Showrunningsysteminformation\n""MPLSinformation\
n""LabelDistributionProtocol\n""IPv4AddressFamily\n""IPv6AddressFamily\n""interf
aceinformation\n"JSON_STR){return(ldp_vty_show_interface(vty,af,json));}DEFPY(ld
p_show_mpls_ldp_capabilities,ldp_show_mpls_ldp_capabilities_cmd,"showmplsldpcapa
bilities[json]$json","Showrunningsysteminformation\n""MPLSinformation\n""LabelDi
stributionProtocol\n""DisplayLDPCapabilitiesinformation\n"JSON_STR){return(ldp_v
ty_show_capabilities(vty,json));}DEFPY(ldp_show_mpls_ldp_neighbor,ldp_show_mpls_
ldp_neighbor_cmd,"showmplsldpneighbor[A.B.C.D]$lsr_id[detail]$detail[json]$json"
,"Showrunningsysteminformation\n""MPLSinformation\n""LabelDistributionProtocol\n
""Neighborinformation\n""NeighborLSR-ID\n""Showdetailedinformation\n"JSON_STR){r
eturn(ldp_vty_show_neighbor(vty,lsr_id_str,0,detail,json));}DEFPY(ldp_show_mpls_
ldp_neighbor_capabilities,ldp_show_mpls_ldp_neighbor_capabilities_cmd,"showmplsl
dpneighbor[A.B.C.D]$lsr_idcapabilities[json]$json","Showrunningsysteminformation
\n""MPLSinformation\n""LabelDistributionProtocol\n""Neighborinformation\n""Neigh
borLSR-ID\n""Displayneighborcapabilityinformation\n"JSON_STR){return(ldp_vty_sho
w_neighbor(vty,lsr_id_str,1,NULL,json));}DEFPY(ldp_show_l2vpn_atom_binding,ldp_s
how_l2vpn_atom_binding_cmd,"showl2vpnatombinding\[{\A.B.C.D$peer\|local-label(16
-1048575)$local_label\|remote-label(16-1048575)$remote_label\}]\[json]$json","Sh
owrunningsysteminformation\n""ShowinformationaboutLayer2VPN\n""ShowAnyTransporto
verMPLSinformation\n""ShowAToMlabelbindinginformation\n""Destinationaddressofthe
VC\n""Matchlocallyassignedlabelvalues\n""Locallyassignedlabelvalue\n""Matchremot
elyassignedlabelvalues\n""Remotelyassignedlabelvalue\n"JSON_STR){if(!local_label
_str)local_label=NO_LABEL;if(!remote_label_str)remote_label=NO_LABEL;return(ldp_
vty_show_atom_binding(vty,peer_str,local_label,remote_label,json));}DEFPY(ldp_sh
ow_l2vpn_atom_vc,ldp_show_l2vpn_atom_vc_cmd,"showl2vpnatomvc\[{\A.B.C.D$peer\|in
terfaceIFNAME$ifname\|vc-id(1-4294967295)$vcid\}]\[json]$json","Showrunningsyste
minformation\n""ShowinformationaboutLayer2VPN\n""ShowAnyTransportoverMPLSinforma
tion\n""ShowAToMvirtualcircuitinformation\n""DestinationaddressoftheVC\n""Locali
nterfaceofthepseudowire\n""Interface'sname\n""VCID\n""VCID\n"JSON_STR){return(ld
p_vty_show_atom_vc(vty,peer_str,ifname,vcid_str,json));}DEFUN_NOSH(ldp_show_debu
gging_mpls_ldp,ldp_show_debugging_mpls_ldp_cmd,"showdebugging[mplsldp]","Showrun
ningsysteminformation\n""Debuggingfunctions\n""MPLSinformation\n""LabelDistribut
ionProtocol\n"){return(ldp_vty_show_debugging(vty));}staticvoidl2vpn_autocomplet
e(vectorcomps,structcmd_token*token){structl2vpn*l2vpn;RB_FOREACH(l2vpn,l2vpn_he
ad,&vty_conf->l2vpn_tree)vector_set(comps,XSTRDUP(MTYPE_COMPLETION,l2vpn->name))
;}staticconststructcmd_variable_handlerl2vpn_var_handlers[]={{.varname="l2vpn_na
me",.completions=l2vpn_autocomplete},{.completions=NULL}};voidldp_vty_init(void)
{cmd_variable_handler_register(l2vpn_var_handlers);install_node(&ldp_node,ldp_co
nfig_write);install_node(&ldp_ipv4_node,NULL);install_node(&ldp_ipv6_node,NULL);
install_node(&ldp_ipv4_iface_node,NULL);install_node(&ldp_ipv6_iface_node,NULL);
install_node(&ldp_l2vpn_node,ldp_l2vpn_config_write);install_node(&ldp_pseudowir
e_node,NULL);install_node(&ldp_debug_node,ldp_debug_config_write);install_defaul
t(LDP_NODE);install_default(LDP_IPV4_NODE);install_default(LDP_IPV6_NODE);instal
l_default(LDP_IPV4_IFACE_NODE);install_default(LDP_IPV6_IFACE_NODE);install_defa
ult(LDP_L2VPN_NODE);install_default(LDP_PSEUDOWIRE_NODE);install_element(CONFIG_
NODE,&ldp_mpls_ldp_cmd);install_element(CONFIG_NODE,&no_ldp_mpls_ldp_cmd);instal
l_element(CONFIG_NODE,&ldp_l2vpn_cmd);install_element(CONFIG_NODE,&no_ldp_l2vpn_
cmd);install_element(CONFIG_NODE,&ldp_debug_mpls_ldp_discovery_hello_cmd);instal
l_element(CONFIG_NODE,&ldp_debug_mpls_ldp_type_cmd);install_element(CONFIG_NODE,
&ldp_debug_mpls_ldp_messages_recv_cmd);install_element(CONFIG_NODE,&ldp_debug_mp
ls_ldp_messages_sent_cmd);install_element(LDP_NODE,&ldp_address_family_cmd);inst
all_element(LDP_NODE,&no_ldp_address_family_cmd);install_element(LDP_NODE,&ldp_d
iscovery_link_holdtime_cmd);install_element(LDP_NODE,&ldp_discovery_targeted_hol
dtime_cmd);install_element(LDP_NODE,&ldp_discovery_link_interval_cmd);install_el
ement(LDP_NODE,&ldp_discovery_targeted_interval_cmd);install_element(LDP_NODE,&l
dp_dual_stack_transport_connection_prefer_ipv4_cmd);install_element(LDP_NODE,&ld
p_dual_stack_cisco_interop_cmd);install_element(LDP_NODE,&ldp_neighbor_password_
cmd);install_element(LDP_NODE,&ldp_neighbor_session_holdtime_cmd);install_elemen
t(LDP_NODE,&ldp_neighbor_ttl_security_cmd);install_element(LDP_NODE,&ldp_router_
id_cmd);install_element(LDP_IPV4_NODE,&ldp_discovery_link_holdtime_cmd);install_
element(LDP_IPV4_NODE,&ldp_discovery_targeted_holdtime_cmd);install_element(LDP_
IPV4_NODE,&ldp_discovery_link_interval_cmd);install_element(LDP_IPV4_NODE,&ldp_d
iscovery_targeted_interval_cmd);install_element(LDP_IPV4_NODE,&ldp_discovery_tar
geted_hello_accept_cmd);install_element(LDP_IPV4_NODE,&ldp_discovery_transport_a
ddress_ipv4_cmd);install_element(LDP_IPV4_NODE,&ldp_label_local_advertise_cmd);i
nstall_element(LDP_IPV4_NODE,&ldp_label_local_advertise_explicit_null_cmd);insta
ll_element(LDP_IPV4_NODE,&ldp_label_local_allocate_cmd);install_element(LDP_IPV4
_NODE,&ldp_label_remote_accept_cmd);install_element(LDP_IPV4_NODE,&ldp_ttl_secur
ity_disable_cmd);install_element(LDP_IPV4_NODE,&ldp_interface_cmd);install_eleme
nt(LDP_IPV4_NODE,&no_ldp_interface_cmd);install_element(LDP_IPV4_NODE,&ldp_sessi
on_holdtime_cmd);install_element(LDP_IPV4_NODE,&ldp_neighbor_ipv4_targeted_cmd);
install_element(LDP_IPV4_NODE,&ldp_exit_address_family_cmd);install_element(LDP_
IPV6_NODE,&ldp_discovery_link_holdtime_cmd);install_element(LDP_IPV6_NODE,&ldp_d
iscovery_targeted_holdtime_cmd);install_element(LDP_IPV6_NODE,&ldp_discovery_lin
k_interval_cmd);install_element(LDP_IPV6_NODE,&ldp_discovery_targeted_interval_c
md);install_element(LDP_IPV6_NODE,&ldp_discovery_targeted_hello_accept_cmd);inst
all_element(LDP_IPV6_NODE,&ldp_discovery_transport_address_ipv6_cmd);install_ele
ment(LDP_IPV6_NODE,&ldp_label_local_advertise_cmd);install_element(LDP_IPV6_NODE
,&ldp_label_local_advertise_explicit_null_cmd);install_element(LDP_IPV6_NODE,&ld
p_label_local_allocate_cmd);install_element(LDP_IPV6_NODE,&ldp_label_remote_acce
pt_cmd);install_element(LDP_IPV6_NODE,&ldp_ttl_security_disable_cmd);install_ele
ment(LDP_IPV6_NODE,&ldp_interface_cmd);install_element(LDP_IPV6_NODE,&ldp_sessio
n_holdtime_cmd);install_element(LDP_IPV6_NODE,&ldp_neighbor_ipv6_targeted_cmd);i
nstall_element(LDP_IPV6_NODE,&ldp_exit_address_family_cmd);install_element(LDP_I
PV4_IFACE_NODE,&ldp_discovery_link_holdtime_cmd);install_element(LDP_IPV4_IFACE_
NODE,&ldp_discovery_link_interval_cmd);install_element(LDP_IPV6_IFACE_NODE,&ldp_
discovery_link_holdtime_cmd);install_element(LDP_IPV6_IFACE_NODE,&ldp_discovery_
link_interval_cmd);install_element(LDP_L2VPN_NODE,&ldp_bridge_cmd);install_eleme
nt(LDP_L2VPN_NODE,&ldp_mtu_cmd);install_element(LDP_L2VPN_NODE,&ldp_member_inter
face_cmd);install_element(LDP_L2VPN_NODE,&ldp_member_pseudowire_cmd);install_ele
ment(LDP_L2VPN_NODE,&no_ldp_member_pseudowire_cmd);install_element(LDP_L2VPN_NOD
E,&ldp_vc_type_cmd);install_element(LDP_PSEUDOWIRE_NODE,&ldp_control_word_cmd);i
nstall_element(LDP_PSEUDOWIRE_NODE,&ldp_neighbor_address_cmd);install_element(LD
P_PSEUDOWIRE_NODE,&ldp_neighbor_lsr_id_cmd);install_element(LDP_PSEUDOWIRE_NODE,
&ldp_pw_id_cmd);install_element(LDP_PSEUDOWIRE_NODE,&ldp_pw_status_disable_cmd);
install_element(ENABLE_NODE,&ldp_clear_mpls_ldp_neighbor_cmd);install_element(EN
ABLE_NODE,&ldp_debug_mpls_ldp_discovery_hello_cmd);install_element(ENABLE_NODE,&
ldp_debug_mpls_ldp_type_cmd);install_element(ENABLE_NODE,&ldp_debug_mpls_ldp_mes
sages_recv_cmd);install_element(ENABLE_NODE,&ldp_debug_mpls_ldp_messages_sent_cm
d);install_element(VIEW_NODE,&ldp_show_mpls_ldp_binding_cmd);install_element(VIE
W_NODE,&ldp_show_mpls_ldp_discovery_cmd);install_element(VIEW_NODE,&ldp_show_mpl
s_ldp_interface_cmd);install_element(VIEW_NODE,&ldp_show_mpls_ldp_capabilities_c
md);install_element(VIEW_NODE,&ldp_show_mpls_ldp_neighbor_cmd);install_element(V
IEW_NODE,&ldp_show_mpls_ldp_neighbor_capabilities_cmd);install_element(VIEW_NODE
,&ldp_show_l2vpn_atom_binding_cmd);install_element(VIEW_NODE,&ldp_show_l2vpn_ato
m_vc_cmd);install_element(VIEW_NODE,&ldp_show_debugging_mpls_ldp_cmd);}