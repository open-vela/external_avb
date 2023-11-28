
/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <libavb/avb_rsa.h>
#include <libavb/avb_util.h>

#include "avb_crypto_ops_impl.h"

#define AVB_RSA_E 65537

static void avb_rsa_be32toh(void *dst, size_t len, const void *src) {
  int i;
  uint32_t *dst32 = (uint32_t *)dst;
  uint32_t *src32 = (uint32_t *)src;

  for (i = 0; i < len; i++) {
    dst32[i] = avb_be32toh(src32[len - i - 1]);
  }
}

bool avb_rsa_verify(const uint8_t* key,
                    size_t key_num_bytes,
                    const uint8_t* sig,
                    size_t sig_num_bytes,
                    const uint8_t* hash,
                    size_t hash_num_bytes,
                    const uint8_t* padding,
                    size_t padding_num_bytes) {
  int ret = -EINVAL;
  int e = AVB_RSA_E;
  uint8_t *n_he;
  uint8_t *sig_he;
  uint8_t *hash_he;
  uint8_t *padding_he;
  avb_cryptodev_context_t ctx;
  AvbRSAPublicKeyHeader h;

  if (!avb_rsa_public_key_header_validate_and_byteswap(
          (const AvbRSAPublicKeyHeader*)key, &h)) {
    avb_error("Invalid key.\n");
    return false;
  }

  n_he = (uint8_t*)avb_malloc(h.key_num_bits / 8);
  sig_he = (uint8_t*)avb_malloc(sig_num_bytes);
  hash_he = (uint8_t*)avb_malloc(hash_num_bytes);
  padding_he = (uint8_t*)avb_malloc(padding_num_bytes);
  if (sig_he == NULL || n_he == NULL || hash_he == NULL || padding_he == NULL) {
    avb_error("Not sufficient buffer.\n");
    goto cleanup;
  }

  avb_rsa_be32toh(sig_he, sig_num_bytes / 4, sig);
  avb_rsa_be32toh(n_he, h.key_num_bits / 32, key + sizeof(AvbRSAPublicKeyHeader));
  avb_rsa_be32toh(padding_he, padding_num_bytes / 4, padding);
  avb_rsa_be32toh(hash_he, hash_num_bytes / 4, hash);

  ret = avb_cryptodev_init(&ctx);
  if (ret < 0) {
    avb_error("Fail to init cryptodev.\n");
    goto cleanup;
  }

  ctx.cryptk.crk_op = CRK_RSA_PKCS15_VERIFY;
  ctx.cryptk.crk_iparams = 5;
  ctx.cryptk.crk_oparams = 0;

  ctx.cryptk.crk_param[0].crp_p = (caddr_t)&e;
  ctx.cryptk.crk_param[0].crp_nbits = sizeof(e) * 8;
  ctx.cryptk.crk_param[1].crp_p = (caddr_t)n_he;
  ctx.cryptk.crk_param[1].crp_nbits = h.key_num_bits;
  ctx.cryptk.crk_param[2].crp_p = (caddr_t)sig_he;
  ctx.cryptk.crk_param[2].crp_nbits = sig_num_bytes * 8;
  ctx.cryptk.crk_param[3].crp_p = (caddr_t)hash_he;
  ctx.cryptk.crk_param[3].crp_nbits = hash_num_bytes * 8;
  ctx.cryptk.crk_param[4].crp_p = (caddr_t)padding_he;
  ctx.cryptk.crk_param[4].crp_nbits = padding_num_bytes * 8;

  ret = avb_cryptodev_cryptk(&ctx);
  if (ret < 0) {
    goto cleanup;
  }

  ret = ctx.cryptk.crk_status;
  avb_cryptodev_free(&ctx);

cleanup:
  avb_free(n_he);
  avb_free(sig_he);
  avb_free(hash_he);
  avb_free(padding_he);
  return ret == 0;
}
