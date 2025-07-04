#define BORINGSSL_PREFIX CKyberBoringSSL
// This file is generated from a similarly-named Perl script in the BoringSSL
// source tree. Do not edit by hand.

#include <CKyberBoringSSL_asm_base.h>

#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && defined(__APPLE__)
.text	




.globl	_CRYPTO_rdrand
.private_extern _CRYPTO_rdrand

.p2align	4
_CRYPTO_rdrand:

_CET_ENDBR
	xorq	%rax,%rax
.byte	72,15,199,242

	adcq	%rax,%rax
	movq	%rdx,0(%rdi)
	ret







.globl	_CRYPTO_rdrand_multiple8_buf
.private_extern _CRYPTO_rdrand_multiple8_buf

.p2align	4
_CRYPTO_rdrand_multiple8_buf:

_CET_ENDBR
	testq	%rsi,%rsi
	jz	L$out
	movq	$8,%rdx
L$loop:
.byte	72,15,199,241
	jnc	L$err
	movq	%rcx,0(%rdi)
	addq	%rdx,%rdi
	subq	%rdx,%rsi
	jnz	L$loop
L$out:
	movq	$1,%rax
	ret
L$err:
	xorq	%rax,%rax
	ret


#endif
#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

