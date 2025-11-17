/*
 * Copyright (C) 2016 The Android Open Source Project
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

#if !defined(AVB_INSIDE_LIBAVB_USER_H) && !defined(AVB_COMPILATION)
#error "Never include this file directly, include libavb_user.h instead."
#endif

#ifndef AVB_VERIFY_H_
#define AVB_VERIFY_H_

#include <libavb/libavb.h>

#ifdef __cplusplus
extern "C" {
#endif

struct avb_hash_desc_t {
  uint64_t image_size;
  uint8_t hash_algorithm[32]; /* Ref: struct AvbHashDescriptor */
  uint32_t salt_len;
  uint8_t salt[64];
  uint32_t digest_len;
  uint8_t digest[64]; /* Max: sha512 */
};

struct avb_params_t {
  const char* const* partition;
  const char* image;
  const char* key;
  const char* suffix;
  const char* vbmeta;
  AvbSlotVerifyFlags flags;
};

/* Verifies the given image using the given key. Returns 0 on success
 * and -1 on failure.
 *
 * The |params| argument is a struct containing the following fields:
 *   const char* partition: Name of the partition to verify.
 *   const char* image: Path to the image to verify.
 *   const char* key: Path to the public key to use for verification.
 *   const char* suffix: Suffix to use for the partition.
 *   AvbSlotVerifyFlags flags: Flags to use for verification.
 *   void* user_data: User data to pass to the AvbOps instance.
 */
int avb_verify(struct avb_params_t* params);

/* Returns the hash descriptor for the given partition. Returns 0 on success
 * and -1 on failure.
 *
 * The |full_partition_name| argument is the full name of the partition to
 * get the hash descriptor for.
 * The |desc| argument is a struct containing the following fields:
 *   uint64_t image_size: Size of the image to verify.
 *   uint8_t hash_algorithm[32]: Hash algorithm to use for verification.
 *   uint32_t digest_len: Length of the digest.
 *   uint8_t digest[64]: Digest of the image.
 */
int avb_hash_desc(const char* full_partition_name,
                  struct avb_hash_desc_t* desc);

/* Returns the hash descriptor for the given partition. Returns 0 on success
 * and -1 on failure.
 *
 * The |vbmeta_partition_name| argument is the name of the vbmeta partition
 * containing the hash descriptor for the given partition.
 * The |full_partition_name| argument is the full name of the partition to
 * verify.
 * The |desc| argument is a struct containing the following fields:
 *   uint64_t image_size: Size of the image to verify.
 *   uint8_t hash_algorithm[32]: Hash algorithm to use for verification.
 *   uint32_t digest_len: Length of the digest.
 *   uint8_t digest[64]: Digest of the image.
 */
int avb_vbmeta_hash_desc(const char* vbmeta_partition_name,
                         const char* full_partition_name,
                         struct avb_hash_desc_t* desc);

/* Dumps the hash descriptor to stdout. */
void avb_hash_desc_dump(const struct avb_hash_desc_t* desc);

#ifdef __cplusplus
}
#endif

#endif /* AVB_VERIFY_H_ */
