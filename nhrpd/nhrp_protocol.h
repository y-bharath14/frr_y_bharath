/*nhrp_protocol.h-NHRPprotocoldefinitions**Copyright(c)2007-2012TimoTeräs<timo.t
eras@iki.fi>**ThissoftwareislicensedundertheMITLicense.*SeeMIT-LICENSE.txtforadd
itionaldetails.*/#ifndefNHRP_PROTOCOL_H#defineNHRP_PROTOCOL_H#include<stdint.h>/
*NHRPEthernetprotocolnumber*/#defineETH_P_NHRP0x2001/*NHRPVersion*/#defineNHRP_V
ERSION_RFC23321/*NHRPPacketTypes*/#defineNHRP_PACKET_RESOLUTION_REQUEST1#defineN
HRP_PACKET_RESOLUTION_REPLY2#defineNHRP_PACKET_REGISTRATION_REQUEST3#defineNHRP_
PACKET_REGISTRATION_REPLY4#defineNHRP_PACKET_PURGE_REQUEST5#defineNHRP_PACKET_PU
RGE_REPLY6#defineNHRP_PACKET_ERROR_INDICATION7#defineNHRP_PACKET_TRAFFIC_INDICAT
ION8#defineNHRP_PACKET_MAX8/*NHRPExtensionTypes*/#defineNHRP_EXTENSION_FLAG_COMP
ULSORY0x8000#defineNHRP_EXTENSION_END0#defineNHRP_EXTENSION_PAYLOAD0#defineNHRP_
EXTENSION_RESPONDER_ADDRESS3#defineNHRP_EXTENSION_FORWARD_TRANSIT_NHS4#defineNHR
P_EXTENSION_REVERSE_TRANSIT_NHS5#defineNHRP_EXTENSION_AUTHENTICATION7#defineNHRP
_EXTENSION_VENDOR8#defineNHRP_EXTENSION_NAT_ADDRESS9/*NHRPErrorIndicationCodes*/
#defineNHRP_ERROR_UNRECOGNIZED_EXTENSION1#defineNHRP_ERROR_LOOP_DETECTED2#define
NHRP_ERROR_PROTOCOL_ADDRESS_UNREACHABLE6#defineNHRP_ERROR_PROTOCOL_ERROR7#define
NHRP_ERROR_SDU_SIZE_EXCEEDED8#defineNHRP_ERROR_INVALID_EXTENSION9#defineNHRP_ERR
OR_INVALID_RESOLUTION_REPLY10#defineNHRP_ERROR_AUTHENTICATION_FAILURE11#defineNH
RP_ERROR_HOP_COUNT_EXCEEDED15/*NHRPCIECodes*/#defineNHRP_CODE_SUCCESS0#defineNHR
P_CODE_ADMINISTRATIVELY_PROHIBITED4#defineNHRP_CODE_INSUFFICIENT_RESOURCES5#defi
neNHRP_CODE_NO_BINDING_EXISTS11#defineNHRP_CODE_BINDING_NON_UNIQUE13#defineNHRP_
CODE_UNIQUE_ADDRESS_REGISTERED14/*NHRPFlagsforResolutionrequest/reply*/#defineNH
RP_FLAG_RESOLUTION_SOURCE_IS_ROUTER0x8000#defineNHRP_FLAG_RESOLUTION_AUTHORATIVE
0x4000#defineNHRP_FLAG_RESOLUTION_DESTINATION_STABLE0x2000#defineNHRP_FLAG_RESOL
UTION_UNIQUE0x1000#defineNHRP_FLAG_RESOLUTION_SOURCE_STABLE0x0800#defineNHRP_FLA
G_RESOLUTION_NAT0x0002/*NHRPFlagsforRegistrationrequest/reply*/#defineNHRP_FLAG_
REGISTRATION_UNIQUE0x8000#defineNHRP_FLAG_REGISTRATION_NAT0x0002/*NHRPFlagsforPu
rgerequest/reply*/#defineNHRP_FLAG_PURGE_NO_REPLY0x8000/*NHRPAuthenticationexten
siontypes(alaCisco)*/#defineNHRP_AUTHENTICATION_PLAINTEXT0x00000001/*NHRPPacketS
tructures*/structnhrp_packet_header{/*Fixedheader*/uint16_tafnum;uint16_tprotoco
l_type;uint8_tsnap[5];uint8_thop_count;uint16_tpacket_size;uint16_tchecksum;uint
16_textension_offset;uint8_tversion;uint8_ttype;uint8_tsrc_nbma_address_len;uint
8_tsrc_nbma_subaddress_len;/*Mandatoryheader*/uint8_tsrc_protocol_address_len;ui
nt8_tdst_protocol_address_len;uint16_tflags;union{uint32_trequest_id;struct{uint
16_tcode;uint16_toffset;}error;}u;}__attribute__((packed));structnhrp_cie_header
{uint8_tcode;uint8_tprefix_length;uint16_tunused;uint16_tmtu;uint16_tholding_tim
e;uint8_tnbma_address_len;uint8_tnbma_subaddress_len;uint8_tprotocol_address_len
;uint8_tpreference;}__attribute__((packed));structnhrp_extension_header{uint16_t
type;uint16_tlength;}__attribute__((packed));structnhrp_cisco_authentication_ext
ension{uint32_ttype;uint8_tsecret[8];}__attribute__((packed));#endif