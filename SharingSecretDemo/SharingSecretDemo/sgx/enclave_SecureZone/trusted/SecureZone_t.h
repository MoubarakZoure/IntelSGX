#ifndef SECUREZONE_T_H__
#define SECUREZONE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_SecureZone_sample(void);
int create_secret(uint8_t* theSecret);
int process_secret(uint8_t* p_dst);

sgx_status_t SGX_CDECL ocall_SecureZone_sample(const char* str);
sgx_status_t SGX_CDECL getRandom(int* retval, int* x);
sgx_status_t SGX_CDECL send_secret(int* retval, uint8_t* secret);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
