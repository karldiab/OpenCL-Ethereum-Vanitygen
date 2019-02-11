/*
 * Vanitygen, vanity bitcoin address generator
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#include <pthread.h>


#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "sha3.h"
#include "pattern.h"
#include "util.h"

#include "ticker.h"
char ticker[10];

int GRSFlag = 0;

const char *version = VANITYGEN_VERSION;


/*
 * Address search thread main loop
 */

void *
vg_thread_loop(void *arg)
{
	unsigned char buf[32];
	unsigned char hash_buf[128], *pend;
	unsigned char eckey_buf[128];
	unsigned char hash1[32];

	int i, c, len, output_interval;
	int hash_len;

	const BN_ULONG rekey_max = 10000000;
	BN_ULONG npoints, rekey_at, nbatch;

	vg_context_t *vcp = (vg_context_t *) arg;
	EC_KEY *pkey = NULL;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	const int ptarraysize = 256;
	EC_POINT *ppnt[ptarraysize];
	EC_POINT *pbatchinc;

	vg_test_func_t test_func = vcp->vc_test;
	vg_exec_context_t ctx;
	vg_exec_context_t *vxcp;

	struct timeval tvstart;


	memset(&ctx, 0, sizeof(ctx));
	vxcp = &ctx;

	vg_exec_context_init(vcp, &ctx);

	pkey = vxcp->vxc_key;
	pgroup = EC_KEY_get0_group(pkey);
	pgen = EC_GROUP_get0_generator(pgroup);

	for (i = 0; i < ptarraysize; i++) {
		ppnt[i] = EC_POINT_new(pgroup);
		if (!ppnt[i]) {
			fprintf(stderr, "ERROR: out of memory?\n");
			exit(1);
		}
	}
	pbatchinc = EC_POINT_new(pgroup);
	if (!pbatchinc) {
		fprintf(stderr, "ERROR: out of memory?\n");
		exit(1);
	}

	BN_set_word(vxcp->vxc_bntmp, ptarraysize);
	EC_POINT_mul(pgroup, pbatchinc, vxcp->vxc_bntmp, NULL, NULL,
		     vxcp->vxc_bnctx);
	EC_POINT_make_affine(pgroup, pbatchinc, vxcp->vxc_bnctx);

	npoints = 0;
	rekey_at = 0;
	nbatch = 0;
	vxcp->vxc_key = pkey;
	//vxcp->vxc_binres[0] = vcp->vc_addrtype;
	c = 0;
	output_interval = 1000;
	gettimeofday(&tvstart, NULL);

	while (!vcp->vc_halt) {
			vg_exec_context_upgrade_lock(vxcp);
			/* Generate a new random private key */
			EC_KEY_generate_key(pkey);
			//char privkey_buf[VG_PROTKEY_MAX_B58];
			//vg_encode_privkey(pkey, vcp->vc_privtype, privkey_buf);
			//printf("generated privkey %s\n",privkey_buf);
			npoints = 0;

			/* Determine rekey interval */
			EC_GROUP_get_order(pgroup, vxcp->vxc_bntmp,
					   vxcp->vxc_bnctx);
			BN_sub(vxcp->vxc_bntmp2,
			       vxcp->vxc_bntmp,
			       EC_KEY_get0_private_key(pkey));
			rekey_at = BN_get_word(vxcp->vxc_bntmp2);


			npoints++;
			vxcp->vxc_delta = 0;


			for (nbatch = 1;
			     (nbatch < ptarraysize) && (npoints < rekey_at);
			     nbatch++, npoints++) {
				EC_POINT_add(pgroup,
					     ppnt[nbatch],
					     ppnt[nbatch-1],
					     pgen, vxcp->vxc_bnctx);
			}

		for (i = 0; i < nbatch; i++, vxcp->vxc_delta++) {
			EC_KEY_generate_key(pkey);
			pend = eckey_buf;
			len = i2o_ECPublicKey(pkey, &pend);
			// printf("\n\nmy priv key: ");
			// dumpbn(EC_KEY_get0_private_key(pkey));
			// printf("pubkey after: ");
			// for (int k = 0; k < 65;k++)
			// printf("%02x",eckey_buf[k]);
			// printf("\n");
			//SHA256(hash_buf, hash_len, hash1);
			//RIPEMD160(hash1, sizeof(hash1), &vxcp->vxc_binres[1]);
			//sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, &eckey_buf[1], 64, buf, sizeof(buf));
			sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, eckey_buf+1, 64, vxcp->vxc_binres, 32);
			// printf("ETH address generated: 0x");
			// for (int k = 12; k < 32;k++)
			// printf("%02x",vxcp->vxc_binres[k]);
			// printf("\n");

			switch (test_func(vxcp, vcp)) {
			case 1:
				npoints = 0;
				rekey_at = 0;
				i = nbatch;
				break;
			case 2:
				goto out;
			default:
				break;
			}
		}

		c += i;
		if (c >= output_interval) {
			output_interval = vg_output_timing(vcp, c, &tvstart);
			if (output_interval > 250000)
				output_interval = 250000;
			c = 0;
		}

		vg_exec_context_yield(vxcp);
	}

out:
	vg_exec_context_del(&ctx);
	vg_context_thread_exit(vcp);

	for (i = 0; i < ptarraysize; i++)
		if (ppnt[i])
			EC_POINT_free(ppnt[i]);
	if (pbatchinc)
		EC_POINT_free(pbatchinc);
	return NULL;
}


#if !defined(_WIN32)
int
count_processors(void)
{
#if defined(__APPLE__)
    int count = sysconf(_SC_NPROCESSORS_ONLN);
#else
	FILE *fp;
	char buf[512];
	int count = 0;

	fp = fopen("/proc/cpuinfo", "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp)) {
		if (!strncmp(buf, "processor\t", 10))
			count += 1;
	}
	fclose(fp);
#endif
    return count;
}
#endif

int
start_threads(vg_context_t *vcp, int nthreads)
{
	pthread_t thread;

	if (nthreads <= 0) {
		/* Determine the number of threads */
		nthreads = count_processors();
		if (nthreads <= 0) {
			fprintf(stderr,
				"ERROR: could not determine processor count\n");
			nthreads = 1;
		}
	}

	if (vcp->vc_verbose > 1) {
		fprintf(stderr, "Using %d worker thread(s)\n", nthreads);
	}

	while (--nthreads) {
		if (pthread_create(&thread, NULL, vg_thread_loop, vcp))
			return 0;
	}

	vg_thread_loop(vcp);
	return 1;
}


void
usage(const char *name)
{
	fprintf(stderr,
"Vanitygen %s (" OPENSSL_VERSION_TEXT ")\n"
"Usage: %s [-vqnrik1NT] [-t <threads>] [-f <filename>|-] [<pattern>...]\n"
"Generates a bitcoin receiving address matching <pattern>, and outputs the\n"
"address and associated private key.  The private key may be stored in a safe\n"
"location or imported into a bitcoin client to spend any balance received on\n"
"the address.\n"
"By default, <pattern> is interpreted as an exact prefix.\n"
"\n"
"Options:\n"
"-v            Verbose output\n"
"-q            Quiet output\n"
"-n            Simulate\n"
"-r            Use regular expression match instead of prefix\n"
"              (Feasibility of expression is not checked)\n"
"-i            Case-insensitive prefix search\n"
"-k            Keep pattern and continue search after finding a match\n"
"-1            Stop after first match\n"
"-a <amount>   Stop after generating <amount> addresses/keys\n"
"-t <threads>  Set number of worker threads (Default: number of CPUs)\n"
"-f <file>     File containing list of patterns, one per line\n"
"              (Use \"-\" as the file name for stdin)\n"
"-o <file>     Write pattern matches to <file>\n"
"-s <file>     Seed random number generator from <file>\n"
"-Z <prefix>   Private key prefix in hex (1Address.io Dapp front-running protection)\n"
"-z            Format output of matches in CSV(disables verbose mode)\n"
"              Output as [COIN],[PREFIX],[ADDRESS],[PRIVKEY]\n",
version, name);
}

#define MAX_FILE 4

int
main(int argc, char **argv)
{
	
	int addrtype = 0;
	int scriptaddrtype = 5;
	int privtype = 128;
	int pubkeytype;
	enum vg_format format = VCF_PUBKEY;
	int regex = 0;
	int caseinsensitive = 0;
	int verbose = 1;
	int simulate = 0;
	int remove_on_match = 1;
	int only_one = 0;
	int numpairs = 0;
	int csv = 0;
	int prompt_password = 0;
	int opt;
	char *seedfile = NULL;
	char pwbuf[128];
	const char *result_file = NULL;
	const char *key_password = NULL;
	char **patterns;
	int npatterns = 0;
	int nthreads = 0;
	vg_context_t *vcp = NULL;
	EC_POINT *pubkey_base = NULL;
	char privkey_prefix[32];
	int privkey_prefix_length = 0;

	FILE *pattfp[MAX_FILE], *fp;
	int pattfpi[MAX_FILE];
	int npattfp = 0;
	int pattstdin = 0;
	int compressed = 0;

	int i;

	while ((opt = getopt(argc, argv, "vqnrik1z:t:h?f:o:s:Z:a:")) != -1) {
		switch (opt) {
		case 'c':
		        compressed = 1;
		        break;
		case 'v':
			verbose = 2;
			break;
		case 'q':
			verbose = 0;
			break;
		case 'n':
			simulate = 1;
			break;
		case 'r':
			regex = 1;
			break;
		case 'i':
			caseinsensitive = 1;
			break;
		case 'k':
			remove_on_match = 0;
			break;
		case 'a':
			remove_on_match = 0;
			numpairs = atoi(optarg);
			break;
		case '1':
			only_one = 1;
			break;
		case 'z':
			csv = 1;
			break;
		case 't':
			nthreads = atoi(optarg);
			if (nthreads == 0) {
				fprintf(stderr,
					"Invalid thread count '%s'\n", optarg);
				return 1;
			}
			break;
		case 'f':
			if (npattfp >= MAX_FILE) {
				fprintf(stderr,
					"Too many input files specified\n");
				return 1;
			}
			if (!strcmp(optarg, "-")) {
				if (pattstdin) {
					fprintf(stderr, "ERROR: stdin "
						"specified multiple times\n");
					return 1;
				}
				fp = stdin;
			} else {
				fp = fopen(optarg, "r");
				if (!fp) {
					fprintf(stderr,
						"Could not open %s: %s\n",
						optarg, strerror(errno));
					return 1;
				}
			}
			pattfp[npattfp] = fp;
			pattfpi[npattfp] = caseinsensitive;
			npattfp++;
			break;
		case 'o':
			if (result_file) {
				fprintf(stderr,
					"Multiple output files specified\n");
				return 1;
			}
			result_file = optarg;
			break;
		case 's':
			if (seedfile != NULL) {
				fprintf(stderr,
					"Multiple RNG seeds specified\n");
				return 1;
			}
			seedfile = optarg;
			break;
		case 'Z':
			assert(strlen(optarg) % 2 == 0);
			privkey_prefix_length = strlen(optarg)/2;
			for (size_t i = 0; i < privkey_prefix_length; i++) {
				int value; // Can't sscanf directly to char array because of overlapping on Win32
				sscanf(&optarg[i*2], "%2x", &value);
				privkey_prefix[privkey_prefix_length - 1 - i] = value;
			}
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	/* Complain about older versions of OpenSSL */
	if (verbose > 0) {
		fprintf(stderr,
			"WARNING: Built with " OPENSSL_VERSION_TEXT "\n"
			"WARNING: Use OpenSSL 1.0.0d+ for best performance\n");
	}
#endif

	if (caseinsensitive && regex)
		fprintf(stderr,
			"WARNING: case insensitive mode incompatible with "
			"regular expressions\n");

	pubkeytype = addrtype;
	if (format == VCF_SCRIPT)
	{
		if (scriptaddrtype == -1)
		{
			fprintf(stderr,
				"Address type incompatible with script format\n");
			return 1;
		}
		addrtype = scriptaddrtype;
	}

	if (seedfile) {
		opt = -1;
#if !defined(_WIN32)
		{	struct stat st;
			if (!stat(seedfile, &st) &&
			    (st.st_mode & (S_IFBLK|S_IFCHR))) {
				opt = 32;
		} }
#endif
		opt = RAND_load_file(seedfile, opt);
		if (!opt) {
			fprintf(stderr, "Could not load RNG seed %s\n", optarg);
			return 1;
		}
		if (verbose > 0) {
			fprintf(stderr,
				"Read %d bytes from RNG seed file\n", opt);
		}
	}

	if (regex) {
		vcp = vg_regex_context_new(addrtype, privtype);

	} else {
		vcp = vg_prefix_context_new(addrtype, privtype,
					    caseinsensitive);
	}

	vcp->vc_compressed = compressed;
	vcp->vc_verbose = verbose;
	vcp->vc_result_file = result_file;
	vcp->vc_remove_on_match = remove_on_match;
	vcp->vc_numpairs = numpairs;
	vcp->vc_csv = csv;
	vcp->vc_only_one = only_one;
	vcp->vc_format = format;
	vcp->vc_pubkeytype = pubkeytype;
	vcp->vc_pubkey_base = pubkey_base;
	//vcp->vc_search_patterns = hashmap_new();
	memcpy(vcp->vc_privkey_prefix, privkey_prefix, privkey_prefix_length);
	vcp->vc_privkey_prefix_length = privkey_prefix_length;

	vcp->vc_output_match = vg_output_match_console;
	vcp->vc_output_timing = vg_output_timing_console;

	if (!npattfp) {
		if (optind >= argc) {
			usage(argv[0]);
			return 1;
		}
		patterns = &argv[optind];
		npatterns = argc - optind;
		vcp->vc_search_patterns = (char**)calloc(npatterns,sizeof(char*));
		for (size_t count = 0; count < npatterns;count++) {
			vcp->vc_search_patterns[count] = (char*)calloc(32,sizeof(char));
		}
		vcp->vc_pattern_strings = (char**)calloc(npatterns,sizeof(char*));
		for (size_t count = 0; count < npatterns;count++) {
			vcp->vc_pattern_strings[count] = (char*)calloc(32,sizeof(char));
		}
		if (!vg_context_add_patterns(vcp,
					     (const char const **) patterns,
					     npatterns))
		return 1;
	}

	for (i = 0; i < npattfp; i++) {
		fp = pattfp[i];
		if (!vg_read_file(fp, &patterns, &npatterns)) {
			fprintf(stderr, "Failed to load pattern file\n");
			return 1;
		}
		if (fp != stdin)
			fclose(fp);

		if (!regex)
			vg_prefix_context_set_case_insensitive(vcp, pattfpi[i]);

		if (!vg_context_add_patterns(vcp,
					     (const char ** const) patterns,
					     npatterns))
		return 1;
	}

	if (!vcp->vc_npatterns) {
		fprintf(stderr, "No patterns to search\n");
		return 1;
	}

	if (prompt_password) {
		if (!vg_read_password(pwbuf, sizeof(pwbuf)))
			return 1;
		key_password = pwbuf;
	}
	vcp->vc_key_protect_pass = key_password;
	if (key_password) {
		if (!vg_check_password_complexity(key_password, verbose))
			fprintf(stderr,
				"WARNING: Protecting private keys with "
				"weak password\n");
	}

	if ((verbose > 0) && regex && (vcp->vc_npatterns > 1))
		fprintf(stderr,
			"Regular expressions: %ld\n", vcp->vc_npatterns);

	if (simulate)
		return 0;

	if (!start_threads(vcp, nthreads))
		return 1;
	return 0;
}
