#define BORINGSSL_PREFIX CKyberBoringSSL
// This file is generated from a similarly-named Perl script in the BoringSSL
// source tree. Do not edit by hand.

#include <CKyberBoringSSL_asm_base.h>

#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && defined(__ELF__)
.text	




.globl	CRYPTO_rdrand
.hidden CRYPTO_rdrand
.type	CRYPTO_rdrand,@function
.align	16
CRYPTO_rdrand:
.cfi_startproc	
_CET_ENDBR
	xorq	%rax,%rax
.byte	72,15,199,242

	adcq	%rax,%rax
	movq	%rdx,0(%rdi)
	ret
.cfi_endproc	
.size	CRYPTO_rdrand,.-CRYPTO_rdrand





.globl	CRYPTO_rdrand_multiple8_buf
.hidden CRYPTO_rdrand_multiple8_buf
.type	CRYPTO_rdrand_multiple8_buf,@function
.align	16
CRYPTO_rdrand_multiple8_buf:
.cfi_startproc	
_CET_ENDBR
	testq	%rsi,%rsi
	jz	.Lout
	movq	$8,%rdx
.Lloop:
.byte	72,15,199,241
	jnc	.Lerr
	movq	%rcx,0(%rdi)
	addq	%rdx,%rdi
	subq	%rdx,%rsi
	jnz	.Lloop
.Lout:
	movq	$1,%rax
	ret
.Lerr:
	xorq	%rax,%rax
	ret
.cfi_endproc	
.size	CRYPTO_rdrand_multiple8_buf,.-CRYPTO_rdrand_multiple8_buf
#endif
#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

