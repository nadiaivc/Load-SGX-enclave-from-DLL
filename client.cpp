/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/


using namespace std;

#ifdef _WIN32
#pragma comment(lib, "crypt32.lib")
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#else
#include "config.h"
#endif

#ifdef _WIN32
// *sigh*
# include "vs/client/Enclave_u.h"
#else
# include "Enclave_u.h"
#endif
#if !defined(SGX_HW_SIM)&&!defined(_WIN32)
#include "sgx_stub.h"
#endif
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <intrin.h>
#include <wincrypt.h>
#include "win32/getopt.h"
#else
#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <sgx_uae_quote_ex.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "sgx_detect.h"
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"
#include "msgio.h"
#include "logfile.h"
#include "quote_size.h"

#define MAX_LEN 80

#ifdef _WIN32
# define strdup(x) _strdup(x)
#else
# define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#endif

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

typedef struct config_struct {
	char mode;
	uint32_t flags;
	sgx_spid_t spid;
	sgx_ec256_public_t pubkey;
	sgx_quote_nonce_t nonce;
	char *server;
	char *port;
} config_t;

int do_quote(sgx_enclave_id_t eid, config_t *config);
int do_attestation(sgx_enclave_id_t eid, config_t *config);

char debug= 0;
char verbose= 0;

#define MODE_ATTEST 0x0
#define MODE_EPID 	0x1
#define MODE_QUOTE	0x2

#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y
#define TOKEN_FILENAME   "Enclave.token"
#ifdef _WIN32
# define ENCLAVE_NAME "Enclave.signed.dll"
#else
# define ENCLAVE_NAME "Enclave.signed.so"
#endif
sgx_enclave_id_t eid = 0;
unsigned long long BaseOfDll;
unsigned long long EndOfDll;

typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char* msg;
	const char* sug; /* Suggestion */
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] = {
	{
		SGX_ERROR_UNEXPECTED,
		"Unexpected error occurred.",
		NULL
	},
	{
		SGX_ERROR_INVALID_PARAMETER,
		"Invalid parameter.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_MEMORY,
		"Out of memory.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_LOST,
		"Power transition occurred.",
		"Please refer to the sample \"PowerTransition\" for details."
	},
	{
		SGX_ERROR_INVALID_ENCLAVE,
		"Invalid enclave image.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ENCLAVE_ID,
		"Invalid enclave identification.",
		NULL
	},
	{
		SGX_ERROR_INVALID_SIGNATURE,
		"Invalid enclave signature.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_EPC,
		"Out of EPC memory.",
		NULL
	},
	{
		SGX_ERROR_NO_DEVICE,
		"Invalid SGX device.",
		"Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
	},
	{
		SGX_ERROR_MEMORY_MAP_CONFLICT,
		"Memory map conflicted.",
		NULL
	},
	{
		SGX_ERROR_INVALID_METADATA,
		"Invalid enclave metadata.",
		NULL
	},
	{
		SGX_ERROR_DEVICE_BUSY,
		"SGX device was busy.",
		NULL
	},
	{
		SGX_ERROR_INVALID_VERSION,
		"Enclave version was invalid.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ATTRIBUTE,
		"Enclave was not authorized.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_FILE_ACCESS,
		"Can't open enclave file.",
		NULL
	},
};

void print_error_message(sgx_status_t ret)
{
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if (ret == sgx_errlist[idx].err) {
			if (NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		printf("Error: Unexpected error occurred.\n");
}


#include <psapi.h>
int work_with_enclave(void)
{
	DWORD processID = GetCurrentProcessId();
	if (!processID) printf("Process ID not found");

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (!hProcess) printf("OpenProcess");

	if (NULL != hProcess)
	{
		HMODULE hMod[256];
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, hMod, sizeof(hMod),
			&cbNeeded))
		{
			TCHAR szProcessName[MAX_PATH] = "<unknown>";
			int num_modules = cbNeeded / sizeof(HMODULE);

			for (int i = 0; i < num_modules; i++)
			{
				MODULEINFO miInfo;
				if (GetModuleInformation(hProcess, hMod[i], &miInfo, sizeof(miInfo)))
				{
					GetModuleBaseName(hProcess, hMod[i], szProcessName,
						sizeof(szProcessName) / sizeof(TCHAR));
					BaseOfDll = (unsigned long long)miInfo.lpBaseOfDll;
					EndOfDll = BaseOfDll + miInfo.SizeOfImage;
					printf("%s    size: %d\n", szProcessName, miInfo.SizeOfImage);

					enclaveChangeBuffer(eid, BaseOfDll, EndOfDll);

				}
				else
				{
					printf("[Error] VirtualQueryEx: %u", GetLastError());
					return 0;
				}

			}
			CloseHandle(hProcess);
		}
	}
	system("pause");

	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		printf("Error\n");
	return 0;
}

void ocall_print_string(const char* str)
{
	/* Proxy/Bridge will check the length and null-terminate
	 * the input string to prevent buffer overflow.
	 */
	printf("\033[90m[DEBUG]\033[39m <%s>\n", str);
}

int main_ra_attestation ()
{
	config_t config;
	sgx_launch_token_t token= { 0 };
	sgx_status_t status;
	
	int updated= 0;
	int sgx_support;
	uint32_t i;
	EVP_PKEY *service_public_key= NULL;
	char have_spid= 0;
	char flag_stdio= 0;

	memset(&config, 0, sizeof(config));
	config.mode= MODE_ATTEST;

	static struct option long_opt[] =
	{
		{"help",		no_argument,		0, 'h'},		
		{"debug",		no_argument,		0, 'd'},
		{"epid-gid",	no_argument,		0, 'e'},
#ifdef _WIN32
		{"pse-manifest",
						no_argument,    	0, 'm'},
#endif
		{"nonce",		required_argument,	0, 'n'},
		{"nonce-file",	required_argument,	0, 'N'},
		{"rand-nonce",	no_argument,		0, 'r'},
		{"spid",		required_argument,	0, 's'},
		{"spid-file",	required_argument,	0, 'S'},
		{"linkable",	no_argument,		0, 'l'},
		{"pubkey",		optional_argument,	0, 'p'},
		{"pubkey-file",	required_argument,	0, 'P'},
		{"quote",		no_argument,		0, 'q'},
		{"verbose",		no_argument,		0, 'v'},
		{"stdio",		no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

	/* Parse our options */
	verbose = 1;
	
	int c;
	int opt_index= 0;
	unsigned char keyin[64];
	
	if ( strlen(optarg) < 32 ) {
		fprintf(stderr, "SPID must be 32-byte hex string\n");
		exit(1);
	}
	if ( ! from_hexstring((unsigned char *) &config.spid,
		(unsigned char *) optarg, 16) ) {

		fprintf(stderr, "SPID must be 32-byte hex string\n");
		exit(1);
	}
	++have_spid;
	

	
	// Default to localhost
	config.server= strdup("localhost");
	if ( config.server == NULL ) {
		perror("malloc");
		return 1;
	}
	printf("main_ra_attestation\n");
	if ( ! have_spid && config.mode != MODE_EPID ) {
		fprintf(stderr, "SPID required. Use one of --spid or --spid-file \n");
		return 1;
	}
	/* Can we run SGX? */

/*
	sgx_support = get_sgx_support();
	if (sgx_support & SGX_SUPPORT_NO) {
		fprintf(stderr, "This system does not support Intel SGX.\n");
		return 1;
	} else {
		if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
			fprintf(stderr, "Intel SGX is supported on this system but disabled in the BIOS\n");
			return 1;
		}
		else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
			fprintf(stderr, "Intel SGX will be enabled after the next reboot\n");
			return 1;
		}
		else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
			fprintf(stderr, "Intel SGX is supported on this sytem but not available for use\n");
			fprintf(stderr, "The system may lock BIOS support, or the Platform Software is not available\n");
			return 1;
		}
	} */

	/* Launch the enclave */
	/* Are we attesting, or just spitting out a quote? */
	int res = 0;
	if ( config.mode == MODE_ATTEST ) {
		res = do_attestation(eid, &config);
	} else if ( config.mode == MODE_EPID || config.mode == MODE_QUOTE ) {
		do_quote(eid, &config);
	} else {
		fprintf(stderr, "Unknown operation mode.\n");
		return 1;
	}
	if (res == Trusted || res == Trusted_ItsComplicated)
	{

		work_with_enclave();

	}

	return 0;
}

int do_attestation (sgx_enclave_id_t eid, config_t *config)
{
	sgx_status_t status, sgxrv, pse_status;
	sgx_ra_msg1_t msg1;
	sgx_ra_msg2_t *msg2 = NULL;
	sgx_ra_msg3_t *msg3 = NULL;
	ra_msg4_t *msg4 = NULL;
	uint32_t msg0_extended_epid_group_id = 0;

	uint32_t msg3_sz;
	uint32_t flags= config->flags;
	sgx_ra_context_t ra_ctx= 0xdeadbeef;
	int rv;
	MsgIO *msgio;
	size_t msg4sz = 0;
	int enclaveTrusted = NotTrusted; // Not Trusted
	int b_pse= OPT_ISSET(flags, OPT_PSE);
	if ( config->server == NULL ) {
		msgio = new MsgIO();
	} else {
		try {
			msgio = new MsgIO(config->server, (config->port == NULL) ?
				DEFAULT_PORT : config->port);
		}
		catch(...) {
			exit(1);
		}
	}

	/*
	 * WARNING! Normally, the public key would be hardcoded into the
	 * enclave, not passed in as a parameter. Hardcoding prevents
	 * the enclave using an unauthorized key.
	 *
	 * This is diagnostic/test application, however, so we have
	 * the flexibility of a dynamically assigned key.
	 */

	/* Executes an ECALL that runs sgx_ra_init() */
	if ( OPT_ISSET(flags, OPT_PUBKEY) ) {
		fprintf(stderr, "+++ using supplied public key\n");
		status= enclave_ra_init(eid, &sgxrv, config->pubkey, b_pse,
			&ra_ctx, &pse_status);
	} else {
		fprintf(stderr, "+++ using default public key\n");
		status= enclave_ra_init_def(eid, &sgxrv, b_pse, &ra_ctx,
			&pse_status);
	}

	/* Did the ECALL succeed? */
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "enclave_ra_init: %08x\n", status);
		delete msgio;
		return 1;
	}

#ifdef _WIN32
	/* If we asked for a PSE session, did that succeed? */
	if (b_pse) {
		if ( pse_status != SGX_SUCCESS ) {
			fprintf(stderr, "pse_session: %08x\n", pse_status);
			delete msgio;
			return 1;
		}
	}
#endif

	/* Did sgx_ra_init() succeed? */
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_ra_init: %08x\n", sgxrv);
		delete msgio;
		return 1;
	}


	/* Generate msg0 */
	printf("before sgx_get_extended_epid_group_id\n");
	status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
	printf("after sgx_get_extended_epid_group_id\n");
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx); 
		fprintf(stderr, "sgx_get_extended_epid_group_id: %08x\n", status);
		delete msgio;
		return 1;
	}
	//msg0_extended_epid_group_id = 0;
	if ( verbose ) {
		dividerWithText(stderr, "Msg0 Details");
		fprintf(stderr,   "Extended Epid Group ID: ");
		print_hexstring(stderr, &msg0_extended_epid_group_id,
			 sizeof(uint32_t));
		fprintf(stderr, "\n");
		divider(stderr);
	}
 
	/* Generate msg1 */
	
	status= sgx_ra_get_msg1(ra_ctx, eid, sgx_ra_get_ga, &msg1);
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
		delete msgio;
		return 1;
	}

	if ( verbose ) {
		dividerWithText(stderr,"Msg1 Details");
		fprintf(stderr,   "msg1.g_a.gx = ");
		print_hexstring(stderr, msg1.g_a.gx, 32);
		fprintf(stderr, "\nmsg1.g_a.gy = ");
		print_hexstring(stderr, msg1.g_a.gy, 32);
		fprintf(stderr, "\nmsg1.gid    = ");
		print_hexstring(stderr, msg1.gid, 4);
		fprintf(stderr, "\n");
		divider(stderr);
	}

	/*
	 * Send msg0 and msg1 concatenated together (msg0||msg1). We do
	 * this for efficiency, to eliminate an additional round-trip
	 * between client and server. The assumption here is that most
	 * clients have the correct extended_epid_group_id so it's
	 * a waste to send msg0 separately when the probability of a
	 * rejection is astronomically small.
	 *
	 * If it /is/ rejected, then the client has only wasted a tiny
	 * amount of time generating keys that won't be used.
	 */

	
	dividerWithText(stderr, "Copy/Paste Msg0||Msg1 Below to SP");
	msgio->send_partial(&msg0_extended_epid_group_id,
		sizeof(msg0_extended_epid_group_id));
	msgio->send(&msg1, sizeof(msg1));
	divider(stderr);

	fprintf(stderr, "Waiting for msg2\n");

	/* Read msg2 
	 *
	 * msg2 is variable length b/c it includes the revocation list at
	 * the end. msg2 is malloc'd in readZ_msg do free it when done.
	 */

	rv= msgio->read((void **) &msg2, NULL);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg2\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg2\n");
		delete msgio;
		exit(1);
	}

	if ( verbose ) {
		dividerWithText(stderr, "Msg2 Details");
		fprintf(stderr,   "msg2.g_b.gx      = ");
		print_hexstring(stderr, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		fprintf(stderr, "\nmsg2.g_b.gy      = ");
		print_hexstring(stderr, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		fprintf(stderr, "\nmsg2.spid        = ");
		print_hexstring(stderr, &msg2->spid, sizeof(msg2->spid));
		fprintf(stderr, "\nmsg2.quote_type  = ");
		print_hexstring(stderr, &msg2->quote_type, sizeof(msg2->quote_type));
		fprintf(stderr, "\nmsg2.kdf_id      = ");
		print_hexstring(stderr, &msg2->kdf_id, sizeof(msg2->kdf_id));
		fprintf(stderr, "\nmsg2.sign_ga_gb  = ");
		print_hexstring(stderr, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		fprintf(stderr, "\nmsg2.mac         = ");
		print_hexstring(stderr, &msg2->mac, sizeof(msg2->mac));
		fprintf(stderr, "\nmsg2.sig_rl_size = ");
		print_hexstring(stderr, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		fprintf(stderr, "\nmsg2.sig_rl      = ");
		print_hexstring(stderr, &msg2->sig_rl, msg2->sig_rl_size);
		fprintf(stderr, "\n");
		divider(stderr);
	}

	
		fprintf(stderr, "+++ msg2_size = %zu\n",
			sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
	

	/* Process Msg2, Get Msg3  */
	/* object msg3 is malloc'd by SGX SDK, so remember to free when finished */

	msg3 = NULL;

	status = sgx_ra_proc_msg2(ra_ctx, eid,
		sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, 
		sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
	    &msg3, &msg3_sz);

	free(msg2);

	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_proc_msg2: %08x\n", status);

		delete msgio;
		return 1;
	} 

	
		fprintf(stderr, "+++ msg3_size = %u\n", msg3_sz);
	
	                          
	if ( verbose ) {
		dividerWithText(stderr, "Msg3 Details");
		fprintf(stderr,   "msg3.mac         = ");
		print_hexstring(stderr, msg3->mac, sizeof(msg3->mac));
		fprintf(stderr, "\nmsg3.g_a.gx      = ");
		print_hexstring(stderr, msg3->g_a.gx, sizeof(msg3->g_a.gx));
		fprintf(stderr, "\nmsg3.g_a.gy      = ");
		print_hexstring(stderr, msg3->g_a.gy, sizeof(msg3->g_a.gy));
#ifdef _WIN32
		fprintf(stderr, "\nmsg3.ps_sec_prop.sgx_ps_sec_prop_desc = ");
		print_hexstring(stderr, msg3->ps_sec_prop.sgx_ps_sec_prop_desc,
			sizeof(msg3->ps_sec_prop.sgx_ps_sec_prop_desc));
#endif
		fprintf(stderr, "\nmsg3.quote       = ");
		print_hexstring(stderr, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
		fprintf(stderr, "\n");
		divider(stderr);
	}

	dividerWithText(stderr, "Copy/Paste Msg3 Below to SP");
	msgio->send(msg3, msg3_sz);
	divider(stderr);

	if ( msg3 ) {
		free(msg3);
		msg3 = NULL;
	}
 
	/* Read Msg4 provided by Service Provider, then process */
        
	rv= msgio->read((void **)&msg4, &msg4sz);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg4\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg4\n");
		delete msgio;
		exit(1);
	}

	edividerWithText("Enclave Trust Status from Service Provider");

	enclaveTrusted= msg4->status;
	if ( enclaveTrusted == Trusted ) {
		eprintf("Enclave TRUSTED\n");
	}
	else if ( enclaveTrusted == NotTrusted ) {
		eprintf("Enclave NOT TRUSTED\n");
	}
	else if ( enclaveTrusted == Trusted_ItsComplicated ) {
		// Trusted, but client may be untrusted in the future unless it
		// takes action.

		eprintf("Enclave Trust is TRUSTED and COMPLICATED. The client is out of date and\nmay not be trusted in the future depending on the service provider's  policy.\n");
		
		
		msgio->send("hello", sizeof("hello"));
		printf("msgio->send\n");
		
		rv = msgio->read((void**)&msg2, NULL);
		if (rv != NULL) {
			printf("msgio->read %s\n", msg2);
		}
		//////////////////////////////////////////////////////////return trusted/untrusted/error/
	} else {
		// Not Trusted, but client may be able to take action to become
		// trusted.

		eprintf("Enclave Trust is NOT TRUSTED and COMPLICATED. The client is out of date.\n");
	}

	/* check to see if we have a PIB by comparing to empty PIB */
	sgx_platform_info_t emptyPIB;
	memset(&emptyPIB, 0, sizeof (sgx_platform_info_t));

	int retPibCmp = memcmp(&emptyPIB, (void *)(&msg4->platformInfoBlob), sizeof (sgx_platform_info_t));

	if (retPibCmp == 0 ) {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
	} else {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");

		
			eprintf("+++ PIB: " );
			print_hexstring(stderr, &msg4->platformInfoBlob, sizeof (sgx_platform_info_t));
			eprintf("\n");
		

		/* We have a PIB, so check to see if there are actions to take */
		sgx_update_info_bit_t update_info;
		sgx_status_t ret = sgx_report_attestation_status(&msg4->platformInfoBlob, 
			enclaveTrusted, &update_info);

		eprintf("+++ sgx_report_attestation_status ret = 0x%04x\n", ret);

		edivider();

		/* Check to see if there is an update needed */
		if ( ret == SGX_ERROR_UPDATE_NEEDED ) {

			edividerWithText("Platform Update Required");
			eprintf("The following Platform Update(s) are required to bring this\n");
			eprintf("platform's Trusted Computing Base (TCB) back into compliance:\n\n");
			if( update_info.pswUpdate ) {
				eprintf("  * Intel SGX Platform Software needs to be updated to the latest version.\n");
			}

			if( update_info.csmeFwUpdate ) {
				eprintf("  * The Intel Management Engine Firmware Needs to be Updated.  Contact your\n");
				eprintf("    OEM for a BIOS Update.\n");
			}

			if( update_info.ucodeUpdate )  {
				eprintf("  * The CPU Microcode needs to be updated.  Contact your OEM for a platform\n");
				eprintf("    BIOS Update.\n");
			}                                           
			eprintf("\n");
			edivider();      
		}
	}

	/*
	 * If the enclave is trusted, fetch a hash of the the MK and SK from
	 * the enclave to show proof of a shared secret with the service 
	 * provider.
	 */

	if ( enclaveTrusted == Trusted ) {
		sgx_status_t key_status, sha_status;
		sgx_sha256_hash_t mkhash, skhash;

		// First the MK

		eprintf("+++ fetching SHA256(MK)\n");
		status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
			SGX_RA_KEY_MK, &mkhash);
		eprintf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n",
			status);

		eprintf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);
		// Then the SK

		eprintf("+++ fetching SHA256(SK)\n");
		status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
			SGX_RA_KEY_SK, &skhash);
		eprintf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n",
			status);

		eprintf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);
		if ( verbose ) {
			eprintf("SHA256(MK) = ");
			print_hexstring(stderr, mkhash, sizeof(mkhash));
			eprintf("\n");
			eprintf("SHA256(SK) = ");
			print_hexstring(stderr, skhash, sizeof(skhash));
			eprintf("\n");
		}

	}

	free (msg4);

	enclave_ra_close(eid, &sgxrv, ra_ctx);
	delete msgio;

	return enclaveTrusted;
}

/*----------------------------------------------------------------------
 * do_quote()
 *
 * Generate a quote from the enclave.
 *----------------------------------------------------------------------
 * WARNING!
 *
 * DO NOT USE THIS SUBROUTINE AS A TEMPLATE FOR IMPLEMENTING REMOTE
 * ATTESTATION. do_quote() short-circuits the RA process in order 
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation: 
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_calc_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 *----------------------------------------------------------------------
 */

int do_quote(sgx_enclave_id_t eid, config_t *config)
{
	sgx_status_t status, sgxrv;
	sgx_quote_t *quote;
	sgx_report_t report;
	sgx_report_t qe_report;
	sgx_target_info_t target_info;
	sgx_epid_group_id_t epid_gid;
	uint32_t sz= 0;
	uint32_t flags= config->flags;
	sgx_quote_sign_type_t linkable= SGX_UNLINKABLE_SIGNATURE;
#ifdef _WIN32
	sgx_ps_cap_t ps_cap;
	char *pse_manifest = NULL;
	size_t pse_manifest_sz;
	LPTSTR b64quote = NULL;
	DWORD sz_b64quote = 0;
	LPTSTR b64manifest = NULL;
	DWORD sz_b64manifest = 0;
#else
	char  *b64quote= NULL;
	char *b64manifest = NULL;
#endif

 	if (OPT_ISSET(flags, OPT_LINK)) linkable= SGX_LINKABLE_SIGNATURE;

	/* Platform services info. Win32 only. */
#ifdef _WIN32
	if (OPT_ISSET(flags, OPT_PSE)) {
		status = get_pse_manifest_size(eid, &pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest_size: %08x\n",
				status);
			return 1;
		}

		pse_manifest = (char *) malloc(pse_manifest_sz);

		status = get_pse_manifest(eid, &sgxrv, pse_manifest, pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest: %08x\n",
				status);
			return 1;
		}
		if (sgxrv != SGX_SUCCESS) {
			fprintf(stderr, "get_sec_prop_desc_ex: %08x\n",
				sgxrv);
			return 1;
		}
	}
#endif

	/* Get our quote */

	memset(&report, 0, sizeof(report));

	status= sgx_init_quote(&target_info, &epid_gid);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_init_quote: %08x\n", status);
		return 1;
	}

	/* Did they ask for just the EPID? */
	if ( config->mode == MODE_EPID ) {
		printf("%08x\n", *(uint32_t *)epid_gid);
		exit(0);
	}

	status= get_report(eid, &sgxrv, &report, &target_info);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "get_report: %08x\n", status);
		return 1;
	}
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_report: %08x\n", sgxrv);
		return 1;
	}

	// sgx_get_quote_size() has been deprecated, but our PSW may be too old
	// so use a wrapper function.

	if (! get_quote_size(&status, &sz)) {
		fprintf(stderr, "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
		return 1;
	}
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "SGX error while getting quote size: %08x\n", status);
		return 1;
	}

	quote= (sgx_quote_t *) malloc(sz);
	if ( quote == NULL ) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	memset(quote, 0, sz);
	status= sgx_get_quote(&report, linkable, &config->spid,
		(OPT_ISSET(flags, OPT_NONCE)) ? &config->nonce : NULL,
		NULL, 0,
		(OPT_ISSET(flags, OPT_NONCE)) ? &qe_report : NULL, 
		quote, sz);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_get_quote: %08x\n", status);
		return 1;
	}

	/* Print our quote */

#ifdef _WIN32
	// We could also just do ((4 * sz / 3) + 3) & ~3
	// but it's cleaner to use the API.

	if (CryptBinaryToString((BYTE *) quote, sz, CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, NULL, &sz_b64quote) == FALSE) {
		fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded quote length\n");
		return 1;
	}

	b64quote = (LPTSTR)(malloc(sz_b64quote));
	if (b64quote == NULL) {
		perror("malloc");
		return 1;
	}
	if (CryptBinaryToString((BYTE *) quote, sz, CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, b64quote, &sz_b64quote) == FALSE) {
		fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded quote length\n");
		return 1;
	}

	if (OPT_ISSET(flags, OPT_PSE)) {
		if (CryptBinaryToString((BYTE *)pse_manifest, (uint32_t)(pse_manifest_sz), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &sz_b64manifest) == FALSE) {
			fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded manifest length\n");
			return 1;
		}

		b64manifest = (LPTSTR)(malloc(sz_b64manifest));
		if (b64manifest == NULL) {
			free(b64quote);
			perror("malloc");
			return 1;
		}

		if (CryptBinaryToString((BYTE *)pse_manifest, (uint32_t)(pse_manifest_sz), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64manifest, &sz_b64manifest) == FALSE) {
			fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded manifest length\n");
			return 1;
		}
	}

#else
	b64quote= base64_encode((char *) quote, sz);
	if ( b64quote == NULL ) {
		eprintf("Could not base64 encode quote\n");
		return 1;
	}
#endif

	printf("{\n");
	printf("\"isvEnclaveQuote\":\"%s\"", b64quote);
	if ( OPT_ISSET(flags, OPT_NONCE) ) {
		printf(",\n\"nonce\":\"");
		print_hexstring(stdout, &config->nonce, 16);
		printf("\"");
	}

#ifdef _WIN32
	if (OPT_ISSET(flags, OPT_PSE)) {
		printf(",\n\"pseManifest\":\"%s\"", b64manifest);	
	}
#endif
	printf("\n}\n");

#ifdef SGX_HW_SIM
	fprintf(stderr, "WARNING! Built in h/w simulation mode. This quote will not be verifiable.\n");
#endif

	free(b64quote);
#ifdef _WIN32
	if ( b64manifest != NULL ) free(b64manifest);
#endif

	return 0;

}



# include <Shlobj.h>

int init_enclave(void)
{

	char token_path[MAX_PATH] = { '\0' };
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;
	printf("In initialize call\n");
	/* Step 1: try to retrieve the launch token saved by last transaction
	 *         if there is no token, then create a new one.
	 */

	 /* try to get the token saved in CSIDL_LOCAL_APPDATA */
	if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, token_path)) {
		strncpy_s(token_path, _countof(token_path), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}
	else {
		strncat_s(token_path, _countof(token_path), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 2);
	}

	/* open the token file */
	printf("Before open token\n");
	HANDLE token_handler = CreateFileA(token_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
	printf("After open token\n");
	if (token_handler == INVALID_HANDLE_VALUE) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}
	else {
		/* read the token from saved file */
		DWORD read_num = 0;
		ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, NULL);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
		printf("ReadFile readnum %d\n", read_num);
	}


	
	printf("Before create\n");
	ret = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	printf("After create\n");
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
		if (token_handler != INVALID_HANDLE_VALUE)
			CloseHandle(token_handler);
		return -1;
	}

	if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (token_handler != INVALID_HANDLE_VALUE)
			CloseHandle(token_handler);
		return 0;
	}

	/* flush the file cache */
	FlushFileBuffers(token_handler);
	/* set access offset to the begin of the file */
	SetFilePointer(token_handler, 0, NULL, FILE_BEGIN);

	/* write back the token */
	DWORD write_num = 0;
	WriteFile(token_handler, token, sizeof(sgx_launch_token_t), &write_num, NULL);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	CloseHandle(token_handler);
	return 0;
}




int main(VOID)
{
	init_enclave();
	main_ra_attestation();

	return 0;
}


BOOLEAN WINAPI DllMain(IN HINSTANCE hDllHandle,
	IN DWORD     nReason,
	IN LPVOID    Reserved)
{
	switch (nReason)
	{
	case DLL_PROCESS_ATTACH:
		init_enclave();
		main_ra_attestation();
		MessageBox(nullptr, "Success", "Dll Injected", MB_OK | MB_ICONINFORMATION);
		break;
	case DLL_THREAD_ATTACH:
		MessageBox(nullptr, "Sucdddddcess", "Dll Idnjected", MB_OK | MB_ICONINFORMATION);

		break;
	case DLL_PROCESS_DETACH:

		break;
	}

	return TRUE;
}