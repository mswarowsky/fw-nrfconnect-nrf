/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>

#include "common_test.h"
#include <mbedtls/md.h>

/**@brief RIPEMD160 test vectors can be found on LU Leuven website.
 *
 * https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 */
const char flash_data_ripemd_160[4096] = { "1234567890" };


/* RIPEMD160 - Based on KU Leuven */
ITEM_REGISTER(test_vector_hash_ripemd_160_data,
	      test_vector_hash_t test_vector_RIPEMD160_invalid) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_FAIL,
	.p_test_vector_name = TV_NAME("RIPEMD160 invalid hash"),
	.p_input =
		"abc",
	.p_expected_output =
		"5d0689ef49d2fae572b881b123a85ffa21595f36"
};

/* RIPEMD160 - Based on KU Leuven */
ITEM_REGISTER(test_vector_hash_ripemd_160_data,
	      test_vector_hash_t test_vector_RIPEMD160_0) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("RIPEMD160 message_len=0"),
	.p_input =
		"",
	.p_expected_output =
		"9c1185a5c5e9fc54612808977ee8f548b2258d31"
};

/* RIPEMD160 - Based on KU Leuven */
ITEM_REGISTER(test_vector_hash_ripemd_160_data,
	      test_vector_hash_t test_vector_RIPEMD160_1) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("RIPEMD160 message_len=1"),
	.p_input =
		"61",
	.p_expected_output =
		"0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"
};

/* RIPEMD160 - Based on KU Leuven */
ITEM_REGISTER(test_vector_hash_ripemd_160_data,
	      test_vector_hash_t test_vector_RIPEMD160_3) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("RIPEMD160 \"abc\" message_len=3"),
	.p_input =
		"616263",
	.p_expected_output =
		"8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
};

/* RIPEMD160 - Based on KU Leuven */
ITEM_REGISTER(test_vector_hash_ripemd_160_data,
	      test_vector_hash_t test_vector_RIPEMD160_14) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("RIPEMD160 \"message digest\" message_len=14"),
	.p_input =
		"6d65737361676520646967657374",
	.p_expected_output =
		"5d0689ef49d2fae572b881b123a85ffa21595f36"
};


/* RIPEMD160 - Based on KU Leuven */
ITEM_REGISTER(test_vector_hash_ripemd_160_data,
	      test_vector_hash_t test_vector_RIPEMD160_26) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("RIPEMD160 \"a..z\" message_len=26"),
	.p_input =
		"6162636465666768696a6b6c6d6e6f707172737475767778797a",
	.p_expected_output =
		"f71c27109c692c1b56bbdceb5b9d2865b3708dbc"
};

/* RIPEMD160 - Based on KU Leuven */
ITEM_REGISTER(test_vector_hash_ripemd_160_data,
	      test_vector_hash_t test_vector_RIPEMD160_56) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("RIPEMD160 \"abcdbcde...nopq\" message_len=56"),
	.p_input =
		"6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
	.p_expected_output =
		"12a053384a9c0c88e405a06c27dcf49ada62eb2b"
};

/* RIPEMD160 - Based on KU Leuven */
ITEM_REGISTER(test_vector_hash_ripemd_160_data,
	      test_vector_hash_t test_vector_RIPEMD160_60) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("RIPEMD160 \"A...Za..z0...9\" message_len=62"),
	.p_input =
		"4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839",
	.p_expected_output =
		"b0e20b6e3116640286ed3a87a5713079b21f5189"
};

/* RIPEMD160 - Based on KU Leuven */
ITEM_REGISTER(test_vector_hash_ripemd_160_data,
	      test_vector_hash_t test_vector_RIPEMD160_80) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("RIPEMD160 8 times \"1234567890\" message_len=80"),
	.p_input =
		"3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930",
	.p_expected_output =
		"9b752e45573d4b39f4dbd3323cab82bf63326bfb"
};

/* Log test vectors to use the update function in serval itterations with the input (regex) (1234567890(0){4086}){256} */
ITEM_REGISTER(test_vector_hash_384_long_data,
	      test_vector_hash_t test_vector_RIPEMD160_long) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.mode = NO_MODE,
	.chunk_length = 4096,
	.update_iterations = 256,
	.p_test_vector_name = TV_NAME("RIPEMD-160 message_len=1048576"),
	.p_input = flash_data_ripemd_160,
	.p_expected_output =
		"2c06e0ddf8460e85b0186fab6edc97cad94c3aa9"
};

/* Log test vectors to use the update function in serval itterations with the input (regex) (1234567890(0){4086}){256} */
ITEM_REGISTER(test_vector_hash_384_long_data,
	      test_vector_hash_t test_vector_RIPEMD160_long_flash) = {
	.digest_type = MBEDTLS_MD_RIPEMD160,
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.mode = DO_MEMCPY,
	.chunk_length = 4096,
	.update_iterations = 256,
	.p_test_vector_name = TV_NAME("RIPEMD-160 flash memcpy message_len=1048576"),
	.p_input = flash_data_ripemd_160,
	.p_expected_output =
		"2c06e0ddf8460e85b0186fab6edc97cad94c3aa9"
};