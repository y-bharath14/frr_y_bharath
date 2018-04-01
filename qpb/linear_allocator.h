/**linear_allocator.h**@copyrightCopyright(C)2016SprouteNetworks,Inc.**@authorAv
neeshSachdev<avneesh@sproute.com>**ThisfileispartofQuagga.**Quaggaisfreesoftware
;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicenseasp
ublishedbythe*FreeSoftwareFoundation;eitherversion2,or(atyouroption)any*laterver
sion.**Quaggaisdistributedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;wit
houteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.Seeth
eGNU*GeneralPublicLicenseformoredetails.**YoushouldhavereceivedacopyoftheGNUGene
ralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,writetotheFreeSoft
ware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*//**Headerfi
leforthelinearallocator.**Anallocatorthatallocatesmemorybywalkingdowntowardsthee
nd*ofabuffer.Noattemptismadetoreuseblocksthatarefreed*subsequently.Theassumption
isthatthebufferisbigenoughto*coverallocationsforagivenpurpose.*/#include<assert.
h>#include<string.h>#include<stdint.h>#include<stddef.h>/**Alignmentforblockallo
catedbytheallocator.Mustbeapowerof2.*/#defineLINEAR_ALLOCATOR_ALIGNMENT8#defineL
INEAR_ALLOCATOR_ALIGN(value)\(((value)+LINEAR_ALLOCATOR_ALIGNMENT-1)\&~(LINEAR_A
LLOCATOR_ALIGNMENT-1));/**linear_allocator_align_ptr*/staticinlinechar*linear_al
locator_align_ptr(char*ptr){return(char*)LINEAR_ALLOCATOR_ALIGN((intptr_t)ptr);}
typedefstructlinear_allocator_t_{char*buf;/**Currentlocationinthebuffer.*/char*c
ur;/**Endofbuffer.*/char*end;/**Versionnumberoftheallocator,thisisbumpedupwhenth
eallocator*isresetandhelpsidentifiesbadfrees.*/uint32_tversion;/**Thenumberofblo
cksthatarecurrentlyallocated.*/intnum_allocated;}linear_allocator_t;/**linear_al
locator_block_t**Headerstructureatthebeginingofeachblock.*/typedefstructlinear_a
llocator_block_t_{uint32_tflags;/**Theversionoftheallocatorwhenthisblockwasalloc
ated.*/uint32_tversion;chardata[0];}linear_allocator_block_t;#defineLINEAR_ALLOC
ATOR_BLOCK_IN_USE0x01#defineLINEAR_ALLOCATOR_HDR_SIZE(sizeof(linear_allocator_bl
ock_t))/**linear_allocator_block_size**Thetotalamountofspaceablockwilltakeintheb
uffer,*includingthesizeoftheheader.*/staticinlinesize_tlinear_allocator_block_si
ze(size_tuser_size){returnLINEAR_ALLOCATOR_ALIGN(LINEAR_ALLOCATOR_HDR_SIZE+user_
size);}/**linear_allocator_ptr_to_block*/staticinlinelinear_allocator_block_t*li
near_allocator_ptr_to_block(void*ptr){void*block_ptr;block_ptr=((char*)ptr)-offs
etof(linear_allocator_block_t,data);returnblock_ptr;}/**linear_allocator_init*/s
taticinlinevoidlinear_allocator_init(linear_allocator_t*allocator,char*buf,size_
tbuf_len){memset(allocator,0,sizeof(*allocator));assert(linear_allocator_align_p
tr(buf)==buf);allocator->buf=buf;allocator->cur=buf;allocator->end=buf+buf_len;}
/**linear_allocator_reset**Prepareanallocatorforreuse.*****NOTE**Thisimplicitlyf
reesalltheblocksintheallocator.*/staticinlinevoidlinear_allocator_reset(linear_a
llocator_t*allocator){allocator->num_allocated=0;allocator->version++;allocator-
>cur=allocator->buf;}/**linear_allocator_alloc*/staticinlinevoid*linear_allocato
r_alloc(linear_allocator_t*allocator,size_tuser_size){size_tblock_size;linear_al
locator_block_t*block;block_size=linear_allocator_block_size(user_size);if(alloc
ator->cur+block_size>allocator->end){returnNULL;}block=(linear_allocator_block_t
*)allocator->cur;allocator->cur+=block_size;block->flags=LINEAR_ALLOCATOR_BLOCK_
IN_USE;block->version=allocator->version;allocator->num_allocated++;returnblock-
>data;}/**linear_allocator_free*/staticinlinevoidlinear_allocator_free(linear_al
locator_t*allocator,void*ptr){linear_allocator_block_t*block;if(((char*)ptr)<all
ocator->buf||((char*)ptr)>=allocator->end){assert(0);return;}block=linear_alloca
tor_ptr_to_block(ptr);if(block->version!=allocator->version){assert(0);return;}b
lock->flags=block->flags&~LINEAR_ALLOCATOR_BLOCK_IN_USE;if(--allocator->num_allo
cated<0){assert(0);}}