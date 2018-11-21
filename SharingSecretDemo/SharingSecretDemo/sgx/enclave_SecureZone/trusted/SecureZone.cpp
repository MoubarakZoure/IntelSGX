#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "SecureZone.h"
#include "SecureZone_t.h"  /* print_string */
#include "sgx_tcrypto.h"

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...) {
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_SecureZone_sample(buf);
}

int ecall_SecureZone_sample() {
	printf("IN SECUREZONE\n");
	return 0;
}

int create_secret(uint8_t* p_dst) {

	/* Step 1 : Secret Generation : */
	int secret;
	int ret;
	getRandom(&ret, &secret);

	printf("\n   Secret generated --> %d  \n\n", secret);

	/* Step 2 :  Secret Encryption    */

	uint8_t p_ctr[16] = { 4, 3, 2, 1, 0 };
	uint32_t ctr_inc_bits = 32;
	uint32_t src_len = 256;
	uint8_t p_src[src_len] = { 2, 3, 2, 6 };
	uint32_t dst_len = 256;

	sgx_aes_ctr_128bit_key_t p_key[16] = { 0, 7, 7, 8, 3, 1, 4, 4, 9, 8, 0, 0,
			0, 0, 0 };

	sgx_aes_ctr_encrypt((const sgx_aes_ctr_128bit_key_t*) p_key,
			(const uint8_t*) p_src, src_len, p_ctr, ctr_inc_bits, p_dst);
	send_secret(&ret,p_dst);

	return 0;
}

int process_secret(uint8_t *p_dst) {
	sgx_aes_ctr_128bit_key_t p_key[16] = { 0, 7, 7, 8, 3, 1, 4, 4, 9, 8, 0, 0,
			0, 0, 0 };
	uint8_t p_ctr[16] = { 4, 3, 2, 1, 0 };
	uint32_t ctr_inc_bits = 32;
	uint32_t src_len = 256;
	uint8_t p_src[src_len] = { 2, 3, 2, 6 };
	uint32_t dst_len = 256;

	uint8_t d_data[dst_len];
	sgx_aes_ctr_decrypt((const sgx_aes_gcm_128bit_key_t*) p_key, p_dst, dst_len,
			p_ctr, ctr_inc_bits, d_data);

	uint8_t *secret;
	create_secret(secret);

	return 0;

}
