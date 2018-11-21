#include "SecureZone_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_ecall_SecureZone_sample(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_SecureZone_sample_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_SecureZone_sample_t* ms = SGX_CAST(ms_ecall_SecureZone_sample_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_SecureZone_sample();


	return status;
}

static sgx_status_t SGX_CDECL sgx_create_secret(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_create_secret_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_create_secret_t* ms = SGX_CAST(ms_create_secret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_theSecret = ms->ms_theSecret;
	size_t _len_theSecret = sizeof(uint8_t);
	uint8_t* _in_theSecret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_theSecret, _len_theSecret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_theSecret != NULL && _len_theSecret != 0) {
		_in_theSecret = (uint8_t*)malloc(_len_theSecret);
		if (_in_theSecret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_theSecret, _len_theSecret, _tmp_theSecret, _len_theSecret)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = create_secret(_in_theSecret);
err:
	if (_in_theSecret) {
		if (memcpy_s(_tmp_theSecret, _len_theSecret, _in_theSecret, _len_theSecret)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_theSecret);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_process_secret(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_process_secret_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_process_secret_t* ms = SGX_CAST(ms_process_secret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_dst = ms->ms_p_dst;
	size_t _len_p_dst = sizeof(uint8_t);
	uint8_t* _in_p_dst = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_dst, _len_p_dst);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_dst != NULL && _len_p_dst != 0) {
		_in_p_dst = (uint8_t*)malloc(_len_p_dst);
		if (_in_p_dst == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_dst, _len_p_dst, _tmp_p_dst, _len_p_dst)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = process_secret(_in_p_dst);
err:
	if (_in_p_dst) {
		if (memcpy_s(_tmp_p_dst, _len_p_dst, _in_p_dst, _len_p_dst)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_p_dst);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_SecureZone_sample, 0},
		{(void*)(uintptr_t)sgx_create_secret, 0},
		{(void*)(uintptr_t)sgx_process_secret, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][3];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_SecureZone_sample(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_SecureZone_sample_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_SecureZone_sample_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	ocalloc_size += (str != NULL) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_SecureZone_sample_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_SecureZone_sample_t));
	ocalloc_size -= sizeof(ms_ocall_SecureZone_sample_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL getRandom(int* retval, int* x)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_x = sizeof(int);

	ms_getRandom_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_getRandom_t);
	void *__tmp = NULL;

	void *__tmp_x = NULL;

	CHECK_ENCLAVE_POINTER(x, _len_x);

	ocalloc_size += (x != NULL) ? _len_x : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_getRandom_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_getRandom_t));
	ocalloc_size -= sizeof(ms_getRandom_t);

	if (x != NULL) {
		ms->ms_x = (int*)__tmp;
		__tmp_x = __tmp;
		if (memcpy_s(__tmp_x, ocalloc_size, x, _len_x)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_x);
		ocalloc_size -= _len_x;
	} else {
		ms->ms_x = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (x) {
			if (memcpy_s((void*)x, _len_x, __tmp_x, _len_x)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL send_secret(int* retval, uint8_t* secret)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_secret = sizeof(uint8_t);

	ms_send_secret_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_send_secret_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(secret, _len_secret);

	ocalloc_size += (secret != NULL) ? _len_secret : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_send_secret_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_send_secret_t));
	ocalloc_size -= sizeof(ms_send_secret_t);

	if (secret != NULL) {
		ms->ms_secret = (uint8_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, secret, _len_secret)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_secret);
		ocalloc_size -= _len_secret;
	} else {
		ms->ms_secret = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

