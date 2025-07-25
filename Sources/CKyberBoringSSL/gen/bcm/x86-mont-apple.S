#define BORINGSSL_PREFIX CKyberBoringSSL
// This file is generated from a similarly-named Perl script in the BoringSSL
// source tree. Do not edit by hand.

#include <CKyberBoringSSL_asm_base.h>

#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86) && defined(__APPLE__)
.text
.globl	_bn_mul_mont
.private_extern	_bn_mul_mont
.align	4
_bn_mul_mont:
L_bn_mul_mont_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	xorl	%eax,%eax
	movl	40(%esp),%edi
	cmpl	$4,%edi
	jl	L000just_leave
	leal	20(%esp),%esi
	leal	24(%esp),%edx
	addl	$2,%edi
	negl	%edi
	leal	-32(%esp,%edi,4),%ebp
	negl	%edi
	movl	%ebp,%eax
	subl	%edx,%eax
	andl	$2047,%eax
	subl	%eax,%ebp
	xorl	%ebp,%edx
	andl	$2048,%edx
	xorl	$2048,%edx
	subl	%edx,%ebp
	andl	$-64,%ebp
	movl	%esp,%eax
	subl	%ebp,%eax
	andl	$-4096,%eax
	movl	%esp,%edx
	leal	(%ebp,%eax,1),%esp
	movl	(%esp),%eax
	cmpl	%ebp,%esp
	ja	L001page_walk
	jmp	L002page_walk_done
.align	4,0x90
L001page_walk:
	leal	-4096(%esp),%esp
	movl	(%esp),%eax
	cmpl	%ebp,%esp
	ja	L001page_walk
L002page_walk_done:
	movl	(%esi),%eax
	movl	4(%esi),%ebx
	movl	8(%esi),%ecx
	movl	12(%esi),%ebp
	movl	16(%esi),%esi
	movl	(%esi),%esi
	movl	%eax,4(%esp)
	movl	%ebx,8(%esp)
	movl	%ecx,12(%esp)
	movl	%ebp,16(%esp)
	movl	%esi,20(%esp)
	leal	-3(%edi),%ebx
	movl	%edx,24(%esp)
	movl	$-1,%eax
	movd	%eax,%mm7
	movl	8(%esp),%esi
	movl	12(%esp),%edi
	movl	16(%esp),%ebp
	xorl	%edx,%edx
	xorl	%ecx,%ecx
	movd	(%edi),%mm4
	movd	(%esi),%mm5
	movd	(%ebp),%mm3
	pmuludq	%mm4,%mm5
	movq	%mm5,%mm2
	movq	%mm5,%mm0
	pand	%mm7,%mm0
	pmuludq	20(%esp),%mm5
	pmuludq	%mm5,%mm3
	paddq	%mm0,%mm3
	movd	4(%ebp),%mm1
	movd	4(%esi),%mm0
	psrlq	$32,%mm2
	psrlq	$32,%mm3
	incl	%ecx
.align	4,0x90
L0031st:
	pmuludq	%mm4,%mm0
	pmuludq	%mm5,%mm1
	paddq	%mm0,%mm2
	paddq	%mm1,%mm3
	movq	%mm2,%mm0
	pand	%mm7,%mm0
	movd	4(%ebp,%ecx,4),%mm1
	paddq	%mm0,%mm3
	movd	4(%esi,%ecx,4),%mm0
	psrlq	$32,%mm2
	movd	%mm3,28(%esp,%ecx,4)
	psrlq	$32,%mm3
	leal	1(%ecx),%ecx
	cmpl	%ebx,%ecx
	jl	L0031st
	pmuludq	%mm4,%mm0
	pmuludq	%mm5,%mm1
	paddq	%mm0,%mm2
	paddq	%mm1,%mm3
	movq	%mm2,%mm0
	pand	%mm7,%mm0
	paddq	%mm0,%mm3
	movd	%mm3,28(%esp,%ecx,4)
	psrlq	$32,%mm2
	psrlq	$32,%mm3
	paddq	%mm2,%mm3
	movq	%mm3,32(%esp,%ebx,4)
	incl	%edx
L004outer:
	xorl	%ecx,%ecx
	movd	(%edi,%edx,4),%mm4
	movd	(%esi),%mm5
	movd	32(%esp),%mm6
	movd	(%ebp),%mm3
	pmuludq	%mm4,%mm5
	paddq	%mm6,%mm5
	movq	%mm5,%mm0
	movq	%mm5,%mm2
	pand	%mm7,%mm0
	pmuludq	20(%esp),%mm5
	pmuludq	%mm5,%mm3
	paddq	%mm0,%mm3
	movd	36(%esp),%mm6
	movd	4(%ebp),%mm1
	movd	4(%esi),%mm0
	psrlq	$32,%mm2
	psrlq	$32,%mm3
	paddq	%mm6,%mm2
	incl	%ecx
	decl	%ebx
L005inner:
	pmuludq	%mm4,%mm0
	pmuludq	%mm5,%mm1
	paddq	%mm0,%mm2
	paddq	%mm1,%mm3
	movq	%mm2,%mm0
	movd	36(%esp,%ecx,4),%mm6
	pand	%mm7,%mm0
	movd	4(%ebp,%ecx,4),%mm1
	paddq	%mm0,%mm3
	movd	4(%esi,%ecx,4),%mm0
	psrlq	$32,%mm2
	movd	%mm3,28(%esp,%ecx,4)
	psrlq	$32,%mm3
	paddq	%mm6,%mm2
	decl	%ebx
	leal	1(%ecx),%ecx
	jnz	L005inner
	movl	%ecx,%ebx
	pmuludq	%mm4,%mm0
	pmuludq	%mm5,%mm1
	paddq	%mm0,%mm2
	paddq	%mm1,%mm3
	movq	%mm2,%mm0
	pand	%mm7,%mm0
	paddq	%mm0,%mm3
	movd	%mm3,28(%esp,%ecx,4)
	psrlq	$32,%mm2
	psrlq	$32,%mm3
	movd	36(%esp,%ebx,4),%mm6
	paddq	%mm2,%mm3
	paddq	%mm6,%mm3
	movq	%mm3,32(%esp,%ebx,4)
	leal	1(%edx),%edx
	cmpl	%ebx,%edx
	jle	L004outer
	emms
	jmp	L006common_tail
.align	4,0x90
L006common_tail:
	movl	16(%esp),%ebp
	movl	4(%esp),%edi
	leal	32(%esp),%esi
	movl	(%esi),%eax
	movl	%ebx,%ecx
	xorl	%edx,%edx
.align	4,0x90
L007sub:
	sbbl	(%ebp,%edx,4),%eax
	movl	%eax,(%edi,%edx,4)
	decl	%ecx
	movl	4(%esi,%edx,4),%eax
	leal	1(%edx),%edx
	jge	L007sub
	sbbl	$0,%eax
	movl	$-1,%edx
	xorl	%eax,%edx
	jmp	L008copy
.align	4,0x90
L008copy:
	movl	32(%esp,%ebx,4),%esi
	movl	(%edi,%ebx,4),%ebp
	movl	%ecx,32(%esp,%ebx,4)
	andl	%eax,%esi
	andl	%edx,%ebp
	orl	%esi,%ebp
	movl	%ebp,(%edi,%ebx,4)
	decl	%ebx
	jge	L008copy
	movl	24(%esp),%esp
	movl	$1,%eax
L000just_leave:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.byte	77,111,110,116,103,111,109,101,114,121,32,77,117,108,116,105
.byte	112,108,105,99,97,116,105,111,110,32,102,111,114,32,120,56
.byte	54,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121
.byte	32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46
.byte	111,114,103,62,0
#endif  // !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86) && defined(__APPLE__)
#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

