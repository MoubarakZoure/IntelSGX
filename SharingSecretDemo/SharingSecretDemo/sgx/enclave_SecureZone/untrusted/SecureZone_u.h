#ifndef SECUREZONE_U_H__
#define SECUREZONE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_SECUREZONE_SAMPLE_DEFINED__
#define OCALL_SECUREZONE_SAMPLE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_SecureZone_sample, (const char* str));
#endif
#ifndef GETRANDOM_DEFINED__
#define GETRANDOM_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, getRandom, (int* x));
#endif
#ifndef SEND_SECRET_DEFINED__
#define SEND_SECRET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, send_secret, (uint8_t* secret));
#endif

sgx_status_t ecall_SecureZone_sample(sgx_enclave_id_t eid, int* retval);
sgx_status_t create_secret(sgx_enclave_id_t eid, int* retval, uint8_t* theSecret);
sgx_status_t process_secret(sgx_enclave_id_t eid, int* retval, uint8_t* p_dst);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
