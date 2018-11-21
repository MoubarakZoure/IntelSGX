#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <time.h>
#include <sgx_urts.h>
#include "sample.h"
#include "SecureZone_u.h"
#include <sys/socket.h>
#include <arpa/inet.h>

# define MAX_PATH FILENAME_MAX
#include <arpa/inet.h>
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char *msg;
	const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] =
		{ { SGX_ERROR_UNEXPECTED, "Unexpected error occurred.",
		NULL }, { SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.",
		NULL }, { SGX_ERROR_OUT_OF_MEMORY, "Out of memory.",
		NULL }, { SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.",
				"Please refer to the sample \"PowerTransition\" for details." },
				{ SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.",
				NULL }, { SGX_ERROR_INVALID_ENCLAVE_ID,
						"Invalid enclave identification.",
						NULL }, { SGX_ERROR_INVALID_SIGNATURE,
						"Invalid enclave signature.",
						NULL }, { SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.",
				NULL },
				{ SGX_ERROR_NO_DEVICE, "Invalid Intel(R) SGX device.",
						"Please make sure Intel(R) SGX module is enabled in the BIOS, and install Intel(R) SGX driver afterwards." },
				{ SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.",
				NULL }, { SGX_ERROR_INVALID_METADATA,
						"Invalid enclave metadata.",
						NULL }, { SGX_ERROR_DEVICE_BUSY,
						"Intel(R) SGX device was busy.",
						NULL }, { SGX_ERROR_INVALID_VERSION,
						"Enclave version was invalid.",
						NULL }, { SGX_ERROR_INVALID_ATTRIBUTE,
						"Enclave was not authorized.",
						NULL }, { SGX_ERROR_ENCLAVE_FILE_ACCESS,
						"Can't open enclave file.",
						NULL }, };

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if (ret == sgx_errlist[idx].err) {
			if (NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
#include <stdarg.h>
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		printf(
				"Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n",
				ret);
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void) {
	char token_path[MAX_PATH] = { '\0' };
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;
	/* Step 1: retrive the launch token saved by last transaction */

	/* try to get the token saved in $HOME */
	const char *home_dir = getpwuid(getuid())->pw_dir;
	if (home_dir != NULL
			&& (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1)
					<= MAX_PATH) {
		/* compose the token path */
		strncpy(token_path, home_dir, strlen(home_dir));
		strncat(token_path, "/", strlen("/"));
		strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
	} else {
		/* if token path is too long or $HOME is NULL */
		strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}

	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n",
				token_path);
	}
	printf("token_path: %s\n", token_path);
	if (fp != NULL) {
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n",
					token_path);
		}
	}

	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */

	ret = sgx_create_enclave(SECUREZONE_FILENAME, SGX_DEBUG_FLAG, &token,
			&updated, &global_eid, NULL);

	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
		if (fp != NULL)
			fclose(fp);

		return -1;
	}
#include <stdlib.h>
	/* Step 3: save the launch token if it is updated */

	if (updated == FALSE || fp == NULL) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL)
			fclose(fp);
		return 0;
	}

	/* reopen the file with write capablity */
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL)
		return 0;
	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	fclose(fp);

	return 0;
}

/* OCall functions */
void ocall_SecureZone_sample(const char *str) {
	/* Proxy/Bridge will check the length and null-terminate
	 * the input string to prevent buffer overflow.
	 */
	printf("%s", str);
}

int setupServer() {

	int server_fd, new_socket;
	int n, len;
	struct sockaddr_in server_addr, client_addr;
	int opt = 1;
	int PORT = 8080;
	char buf[256];

	if ((server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	// Forcefully attaching socket to the port 8080
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
			sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(PORT);

	if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr))
			< 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	pid_t pid = fork();

	if (pid == 0) {
		printf("-- fils --\n");

		printf("\n\t WAITING FOR REQUESTS %d", pid);
		n = recvfrom(server_fd, (char *) buf, 256, MSG_WAITALL,
				(struct sockaddr *) &server_addr, (socklen_t *) &len);
		printf("\n\t DATA HAS BEEN RECEIVED %s", *buf);

	} else if (pid > 0) {
		printf("-- père--\n");

	} else {

	}

	return 0;

}

/* Application entry */
int main(int argc, char *argv[]) {
	(void) (argc);
	(void) (argv);

	/* Changing dir to where the executable is.*/
	char absolutePath[MAX_PATH];
	char *ptr = NULL;

	ptr = realpath(dirname(argv[0]), absolutePath);

	if (chdir(absolutePath) != 0)
		abort();

	/* Initialize the enclave */
	if (initialize_enclave() < 0) {

		return -1;
	}

// Setting up server

	int server_fd, new_socket;
	int n, len;
	struct sockaddr_in server_addr, client_addr;
	int opt = 1;
	int PORT = 8080;
	char buf[256];

	if ((server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	// Forcefully attaching socket to the port 8080
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
			sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(PORT);

	if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr))
			< 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	printf("\n\t WAITING FOR REQUEST\n");

	n = recvfrom(server_fd, (char *) buf, 256, MSG_WAITALL,
			(struct sockaddr *) &server_addr, (socklen_t *) &len);

// setting up server

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int ecall_return = 0;
	unsigned long l = 256;
	uint8_t* secret;

	ret = create_secret(global_eid, &ecall_return, secret);

	if (ret != SGX_SUCCESS)
		abort();

	/*if (ecall_return == 0) {
	 printf("Application ran with success\n");
	 } else {
	 printf("Application failed %d \n", ecall_return);
	 }*/

	sgx_destroy_enclave(global_eid);

	return ecall_return;
}

/* O_CALL  */

int getRandom(int *x) {
	srand(time(NULL));
	int r = rand();
	*x = r;
	return r;

}

int send_secret(uint8_t *secret) {
	int PORT = 8080;
	struct sockaddr_in address;
	int sock = 0, valread;
	struct sockaddr_in serv_addr;

	char buffer[256] = { 0 };
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	int count = sendto(sock, secret, count, 0, (struct sockaddr *) &serv_addr,
			sizeof(struct sockaddr));

	return 0;

}

