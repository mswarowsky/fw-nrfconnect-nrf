/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <logging/log.h>

#include "common_test.h"
#include <ripedmd160.h>
#include <mbedtls/md.h>

/* Setting LOG_LEVEL_DBG might affect time measurements! */
LOG_MODULE_REGISTER(test_ripemd_160, LOG_LEVEL_INF);

extern test_vector_hash_t __start_test_vector_hash_ripemd_160_data[];
extern test_vector_hash_t __stop_test_vector_hash_ripemd_160_data[];

extern test_vector_hash_t __start_test_vector_hash_ripemd_160_long_data[];
extern test_vector_hash_t __stop_test_vector_hash_ripemd_160_long_data[];

#define INPUT_BUF_SIZE (4125)
#define OUTPUT_BUF_SIZE (64)

static mbedtls_ripemd160_context ripemd_160_context;

static uint8_t m_ripedmd_input_buf[INPUT_BUF_SIZE];
static uint8_t m_ripedmd_output_buf[OUTPUT_BUF_SIZE];
static uint8_t m_ripedmd_expected_output_buf[OUTPUT_BUF_SIZE];

static test_vector_hash_t *p_test_vector;
static uint32_t ripedmd_vector_n;
static uint32_t ripemd_long_vector_n;


static size_t in_len;
static size_t out_len;
static size_t expected_out_len;

void ripemd_160_clear_buffers(void)
{
	memset(m_ripedmd_input_buf, 0x00, sizeof(m_ripedmd_input_buf));
	memset(m_ripedmd_output_buf, 0x00, sizeof(m_ripedmd_output_buf));
	memset(m_ripedmd_expected_output_buf, 0x00,
	       sizeof(m_ripedmd_expected_output_buf));
}

__attribute__((noinline)) static void unhexify_ripedmd(void)
{
	/* Fetch and unhexify test vectors. */
	in_len = hex2bin(p_test_vector->p_input, strlen(p_test_vector->p_input),
			 m_ripedmd_input_buf, strlen(p_test_vector->p_input));
	expected_out_len = hex2bin(p_test_vector->p_expected_output,
				   strlen(p_test_vector->p_expected_output),
				   m_ripedmd_expected_output_buf,
				   strlen(p_test_vector->p_expected_output));
	out_len = expected_out_len;
}

__attribute__((noinline)) static void unhexify_ripemd_long(void)
{
	/* Fetch and unhexify test vectors. */
	in_len = p_test_vector->chunk_length;
	expected_out_len = hex2bin(p_test_vector->p_expected_output,
				   strlen(p_test_vector->p_expected_output),
				   m_ripemd_expected_output_buf,
				   strlen(p_test_vector->p_expected_output));
	out_len = expected_out_len;
	memcpy(m_ripemd_input_buf, p_test_vector->p_input, in_len);
}

void ripemd_160_setup(void)
{
	ripemd_160_clear_buffers();
	p_test_vector = ITEM_GET(test_vector_hash_ripemd_160_data, test_vector_hash_t,
				 ripedmd_vector_n);
	unhexify_ripedmd();
}

void ripemd_160_teardown(void)
{
	ripedmd_vector_n++;
}

__attribute__((noinline)) static void ripemd_160_long_setup(void)
{
	ripemd_160_clear_buffers();
	p_test_vector = ITEM_GET(test_vector_hash_384_long_data,
				 test_vector_hash_t, ripemd_160_long_vector_n);
	unhexify_ripemd_long();
}

static void ripemd_160_long_teardown(void)
{
	ripemd_long_vector_n++;
}

/**@brief Function encapsulating RIPEMD-160 execution steps.
 *
 */
static int exec_ripemd_160(test_vector_hash_t *p_test_vector, int in_len,
		       bool is_long)
{
	mbedtls_ripemd160_init(&ripemd_160_context);
	int err_code = mbedtls_ripemd160_starts_ret(&ripemd_160_context);
	TEST_VECTOR_ASSERT_EQUAL(0, err_code);

	/* Update the hash. */
	if (!is_long) {
		err_code = mbedtls_ripemd160_update_ret(&ripemd_160_context,
						     m_ripedmd_input_buf, in_len);
	} else {
		/* Update the hash until all input data is processed. */
		for (int j = 0; j < p_test_vector->update_iterations; j++) {
			/* Test mode for measuring the memcpy from the flash in RIPEDMD. */
			if (p_test_vector->mode == DO_MEMCPY) {
				memcpy(m_ripedmd_input_buf, p_test_vector->p_input,
				       4096);
			}

			err_code = mbedtls_ripemd160_update_ret(
				&ripemd_160_context, m_ripedmd_input_buf, in_len);
			TEST_VECTOR_ASSERT_EQUAL(
				p_test_vector->expected_err_code, err_code);
		}
	}

	TEST_VECTOR_ASSERT_EQUAL(p_test_vector->expected_err_code, err_code);

	/* Finalize the hash. */
	return mbedtls_ripemd160_finish_ret(&ripemd_160_context, m_ripedmd_output_buf);
}

/**@brief Function for verifying the RIPEDMD-160 digest of messages.
 */
void exec_test_case_ripemd_160(void)
{
	int err_code = -1;

	start_time_measurement();
	err_code = exec_ripemd_160(p_test_vector, in_len, false);
	stop_time_measurement();

	/* Verify the mbedtls_ripemd160_finish_ret err_code. */
	TEST_VECTOR_ASSERT_EQUAL(p_test_vector->expected_err_code, err_code);

	/* Verify the generated digest. */
	TEST_VECTOR_ASSERT_EQUAL(expected_out_len, out_len);
	TEST_VECTOR_MEMCMP_ASSERT(m_ripedmd_output_buf, m_ripedmd_expected_output_buf,
				  expected_out_len,
				  p_test_vector->expected_result,
				  "Incorrect hash");

	/* Do the same in a single step */
	err_code = mbedtls_ripemd160_ret(m_ripedmd_input_buf, in_len, m_ripedmd_output_buf);

	TEST_VECTOR_ASSERT_EQUAL(p_test_vector->expected_err_code, err_code);

	/* Verify the generated digest. */
	TEST_VECTOR_ASSERT_EQUAL(expected_out_len, out_len);
	TEST_VECTOR_MEMCMP_ASSERT(m_ripedmd_output_buf, m_ripedmd_expected_output_buf,
				  expected_out_len,
				  p_test_vector->expected_result,
				  "Incorrect hash");
	mbedtls_ripemd160_free(&ripemd_160_context);
}

/**@brief Function for verifying RIPEMD-160 of long messages.
 */
void exec_test_case_ripemd_160_long(void)
{
	int err_code = -1;

	start_time_measurement();
	err_code = exec_ripemd_160(p_test_vector, in_len, true);
	stop_time_measurement();

	TEST_VECTOR_ASSERT_EQUAL(p_test_vector->expected_err_code, err_code);

	/* Verify the generated digest. */
	TEST_VECTOR_ASSERT_EQUAL(expected_out_len, out_len);
	TEST_VECTOR_MEMCMP_ASSERT(m_ripemd_output_buf, m_ripemd_expected_output_buf,
				  expected_out_len,
				  p_test_vector->expected_result,
				  "Incorrect hash");

	mbedtls_ripemd160_free(&ripemd_160_context);
}

ITEM_REGISTER(test_case_ripemd_160_data, test_case_t test_ripemd_160) = {
	.p_test_case_name = "RIPEMD-160",
	.setup = ripemd_160_setup,
	.exec = exec_test_case_ripemd_160,
	.teardown = ripemd_160_teardown,
	.vector_type = TV_HASH,
	.vectors_start = __start_test_vector_hash_ripemd_160_data,
	.vectors_stop = __stop_test_vector_hash_ripemd_160_data,
};

ITEM_REGISTER(test_case_ripemd_160_data, test_case_t test_ripemd_160_long) = {
	.p_test_case_name = "RIPEMD-160 long",
	.setup = ripemd_160_long_setup,
	.exec = exec_test_case_ripemd_160_long,
	.teardown = ripemd_160_long_teardown,
	.vector_type = TV_HA
	.vectors_start = __start_test_vector_hash_ripemd_160_long_data,
	.vectors_stop = __stop_test_vector_hash_ripemd_160_long_data,
};

