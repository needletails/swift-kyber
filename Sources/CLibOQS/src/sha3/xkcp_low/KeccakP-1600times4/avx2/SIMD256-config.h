#if defined(__x86_64__) || defined(_M_64)
/*
This file defines some parameters of the implementation in the parent directory.
*/

#define KeccakP1600times4_implementation_config "AVX2, all rounds unrolled"
#define KeccakP1600times4_fullUnrolling
#define KeccakP1600times4_useAVX2
#endif
