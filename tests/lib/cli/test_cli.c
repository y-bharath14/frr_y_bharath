/**CLI/commanddummyhandlingtester**Copyright(C)2015byDavidLamparter,*forOpenSour
ceRouting/NetDEF,Inc.**Quaggaisfreesoftware;youcanredistributeitand/ormodifyit*u
nderthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;
eitherversion2,or(atyouroption)any*laterversion.**Quaggaisdistributedinthehopeth
atitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANT
ABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetai
ls.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram
;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,Fif
thFloor,Boston,MA02110-1301USA*/#include<zebra.h>#include"prefix.h"#include"comm
on_cli.h"DUMMY_DEFUN(cmd0,"argipv4A.B.C.D");DUMMY_DEFUN(cmd1,"argipv4mA.B.C.D/M"
);DUMMY_DEFUN(cmd2,"argipv6X:X::X:X$foo");DUMMY_DEFUN(cmd3,"argipv6mX:X::X:X/M")
;DUMMY_DEFUN(cmd4,"argrange(5-15)");DUMMY_DEFUN(cmd5,"pata<a|b>");DUMMY_DEFUN(cm
d6,"patb<a|bA.B.C.D$bar>");DUMMY_DEFUN(cmd7,"patc<a|b|c>A.B.C.D");DUMMY_DEFUN(cm
d8,"patd{fooA.B.C.D$foo|barX:X::X:X$bar|baz}[final]");DUMMY_DEFUN(cmd9,"pate[WOR
D]");DUMMY_DEFUN(cmd10,"patf[key]");DUMMY_DEFUN(cmd11,"altaWORD");DUMMY_DEFUN(cm
d12,"altaA.B.C.D");DUMMY_DEFUN(cmd13,"altaX:X::X:X");DUMMY_DEFUN(cmd14,"patg{foo
A.B.C.D$foo|foo|barX:X::X:X$bar|baz}[final]");#include"lib/cli/test_cli_clippy.c
"DEFPY(magic_test,magic_test_cmd,"magic(0-100){ipv4netA.B.C.D/M|X:X::X:X$ipv6}",
"1\n2\n3\n4\n5\n"){charbuf[256];vty_out(vty,"def:%s\n",self->string);vty_out(vty
,"num:%ld\n",magic);vty_out(vty,"ipv4:%s\n",prefix2str(ipv4net,buf,sizeof(buf)))
;vty_out(vty,"ipv6:%s\n",inet_ntop(AF_INET6,&ipv6,buf,sizeof(buf)));returnCMD_SU
CCESS;}voidtest_init(intargc,char**argv){size_trepeat=argc>1?strtoul(argv[1],NUL
L,0):223;install_element(ENABLE_NODE,&cmd0_cmd);install_element(ENABLE_NODE,&cmd
1_cmd);install_element(ENABLE_NODE,&cmd2_cmd);install_element(ENABLE_NODE,&cmd3_
cmd);install_element(ENABLE_NODE,&cmd4_cmd);install_element(ENABLE_NODE,&cmd5_cm
d);install_element(ENABLE_NODE,&cmd6_cmd);install_element(ENABLE_NODE,&cmd7_cmd)
;install_element(ENABLE_NODE,&cmd8_cmd);install_element(ENABLE_NODE,&cmd9_cmd);i
nstall_element(ENABLE_NODE,&cmd10_cmd);install_element(ENABLE_NODE,&cmd11_cmd);i
nstall_element(ENABLE_NODE,&cmd12_cmd);install_element(ENABLE_NODE,&cmd13_cmd);f
or(size_ti=0;i<repeat;i++){uninstall_element(ENABLE_NODE,&cmd5_cmd);install_elem
ent(ENABLE_NODE,&cmd5_cmd);}for(size_ti=0;i<repeat;i++){uninstall_element(ENABLE
_NODE,&cmd13_cmd);install_element(ENABLE_NODE,&cmd13_cmd);}install_element(ENABL
E_NODE,&cmd14_cmd);install_element(ENABLE_NODE,&magic_test_cmd);}