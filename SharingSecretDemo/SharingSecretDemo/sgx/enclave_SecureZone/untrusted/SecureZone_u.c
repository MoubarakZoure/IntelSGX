#include "SecureZone_u.h"
#include <errno.h>

typedef struct ms_ecall_SecureZone_sample_t {
	int ms_retval;
} ms_ecall_SecureZone_sample_t;

typedef struct ms_create_secret_t {
	int ms_retval;
	uint8_t* ms_theSecret;
} ms_create_secret_t;

typedef struct ms_process_secret_t {
	int ms_retval;
	uint8_t* ms_p_dst;
} ms_process_secret_t;

typedef struct ms_ocall_SecureZone_sample_t {
	const char* ms_str;
} ms_ocall_SecureZone_sample_t;

typedef struct ms_getRandom_t {
	int ms_retval;
	int* ms_x;
} ms_getRandom_t;

typedef struct ms_send_secret_t {
	int ms_retval;
	uint8_t* ms_secret;
} ms_send_secret_t;

static sgx_status_t SGX_CDECL SecureZone_ocall_SecureZone_sample(void* pms)
{
	ms_ocall_SecureZone_sample_t* ms = SGX_CAST(ms_ocall_SecureZone_sample_t*, pms);
	ocall_SecureZone_sample(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL SecureZone_getRandom(void* pms)
{
	ms_getRandom_t* ms = SGX_CAST(ms_getRandom_t*, pms);
	ms->ms_retval = getRandom(ms->ms_x);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL SecureZone_send_secret(void* pms)
{
	ms_send_secret_t* ms = SGX_CAST(ms_send_secret_t*, pms);
	ms->ms_retval = send_secret(ms->ms_secret);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_SecureZone = {
	3,
	{
		(void*)SecureZone_ocall_SecureZone_sample,
		(void*)SecureZone_getRandom,
		(void*)SecureZone_send_secret,
	}
};
sgx_status_t ecall_SecureZone_sample(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_SecureZone_sample_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_SecureZone, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t create_secret(sgx_enclave_id_t eid, int* retval, uint8_t* theSecret)
{
	sgx_status_t status;
	ms_create_secret_t ms;
	ms.ms_theSecret = theSecret;
	status = sgx_ecall(eid, 1, &ocall_table_SecureZone, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t process_secret(sgx_enclave_id_t eid, int* retval, uint8_t* p_dst)
{
	sgx_status_t status;
	ms_process_secret_t ms;
	ms.ms_p_dst = p_dst;
	status = sgx_ecall(eid, 2, &ocall_table_SecureZone, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

