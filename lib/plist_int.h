/**Prefixlistinternaldefinitions.*Copyright(C)1999KunihiroIshiguro**Thisfileispa
rtofGNUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/ormodify*itunderth
etermsoftheGNUGeneralPublicLicenseaspublished*bytheFreeSoftwareFoundation;either
version2,or(atyour*option)anylaterversion.**GNUZebraisdistributedinthehopethatit
willbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABIL
ITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.*
*YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;see
thefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFl
oor,Boston,MA02110-1301USA*/#ifndef_QUAGGA_PLIST_INT_H#define_QUAGGA_PLIST_INT_H
enumprefix_name_type{PREFIX_TYPE_STRING,PREFIX_TYPE_NUMBER};structpltrie_table;s
tructprefix_list{char*name;char*desc;structprefix_master*master;enumprefix_name_
typetype;intcount;intrangecount;structprefix_list_entry*head;structprefix_list_e
ntry*tail;structpltrie_table*trie;structprefix_list*next;structprefix_list*prev;
};/*Eachprefix-list'sentry.*/structprefix_list_entry{intseq;intle;intge;enumpref
ix_list_typetype;intany;structprefixprefix;unsignedlongrefcnt;unsignedlonghitcnt
;structprefix_list_entry*next;structprefix_list_entry*prev;/*upthechainforbestma
tchsearch*/structprefix_list_entry*next_best;};#endif/*_QUAGGA_PLIST_INT_H*/