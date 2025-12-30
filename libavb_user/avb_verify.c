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

#include "avb_verify.h"

#include <stddef.h>
#include <string.h>

#include "avb_ops_user.h"

int avb_verify(struct avb_params_t* params) {
  AvbOps* ops;
  AvbSlotVerifyData* slot_data[2] = {0};
  struct avb_ops_user_data_t user_data = {0};
  const char* image[2] = {NULL, NULL};
  int ret;
  int n;

  if (params == NULL || params->key == NULL || params->partition == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT;
    goto out;
  }

  image[0] = params->image;

  if (!(params->flags & AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION) &&
      params->vbmeta == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT;
    goto out;
  }

  if (params->flags & AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION) {
    params->vbmeta = NULL;
  }

  ops = avb_ops_user_new();
  if (ops == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out;
  }

  user_data.key = params->key;
  user_data.vbmeta = params->vbmeta;
  ops->user_data = &user_data;

  for (n = 0; n < 2; n++) {
    ret = avb_slot_verify(ops,
                          n == 0 ? params->partition : image,
                          params->suffix ? params->suffix : "",
                          params->flags,
                          AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                          &slot_data[n]);

    if (!params->image) {
      goto out_with_ops;
    }
  }

  if (!slot_data[0] || !slot_data[1]) {
    goto out_with_ops;
  }

  for (n = 0; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS; n++) {
    if (slot_data[1]->rollback_indexes[n] < slot_data[0]->rollback_indexes[n]) {
      ret = AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX;
      goto out_with_ops;
    }
  }

out_with_ops:
  avb_ops_user_free(ops);
out:
  for (n = 0; n < 2; n++)
    if (slot_data[n]) avb_slot_verify_data_free(slot_data[n]);
  return ret;
}

int avb_hash_desc(const char* full_partition_name,
                  struct avb_hash_desc_t* desc) {

  return avb_vbmeta_hash_desc(NULL, full_partition_name, desc);
}

int avb_vbmeta_hash_desc(const char* vbmeta_partition_name,
                         const char* full_partition_name,
                         struct avb_hash_desc_t* desc) {
  AvbOps* ops;
  AvbFooter footer;
  size_t vbmeta_num_read;
  uint8_t* vbmeta_buf = NULL;
  size_t num_descriptors;
  const AvbDescriptor** descriptors;
  AvbDescriptor avb_desc;
  int ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
  size_t vbmeta_offset = 0;
  size_t vbmeta_size = VBMETA_MAX_SIZE;

  ops = avb_ops_user_new();
  if (ops == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out;
  }

  if (vbmeta_partition_name == NULL) {
    if (avb_footer(ops, full_partition_name, &footer) != AVB_IO_RESULT_OK) {
      avb_error("Loading footer failed: ", full_partition_name);
      ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
      goto out_with_ops;
    }
    vbmeta_offset = footer.vbmeta_offset;
    vbmeta_size = footer.vbmeta_size;
    vbmeta_partition_name = full_partition_name;
  }

  vbmeta_buf = avb_malloc(vbmeta_size);
  if (vbmeta_buf == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out_with_ops;
  }

  if (ops->read_from_partition(ops,
                               vbmeta_partition_name,
                               vbmeta_offset,
                               vbmeta_size,
                               vbmeta_buf,
                               &vbmeta_num_read) != AVB_IO_RESULT_OK ||
      vbmeta_num_read != vbmeta_size) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
    goto out_with_buf;
  }

  descriptors =
      avb_descriptor_get_all(vbmeta_buf, vbmeta_num_read, &num_descriptors);
  if (!descriptors) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
    goto out_with_buf;
  }

  for (; num_descriptors > 0; num_descriptors--, descriptors++) {
    if (!avb_descriptor_validate_and_byteswap(*descriptors, &avb_desc)) {
      avb_error(vbmeta_partition_name, ": Descriptor is invalid.\n");
      ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
      goto out_with_buf;
    }

    if (avb_desc.tag == AVB_DESCRIPTOR_TAG_HASH) {
      AvbHashDescriptor avb_hash_desc;
      const AvbDescriptor* descriptor = *descriptors;
      const uint8_t* desc_partition_name = NULL;
      const uint8_t* desc_salt;
      const uint8_t* desc_digest;

      if (!avb_hash_descriptor_validate_and_byteswap(
              (const AvbHashDescriptor*)descriptor, &avb_hash_desc)) {
        ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
        goto out_with_buf;
      }

      if (avb_strlen(full_partition_name) != avb_hash_desc.partition_name_len) {
        continue;
      }

      desc_partition_name = ((const uint8_t*)descriptor) + sizeof(AvbHashDescriptor);
      if (avb_memcmp(desc_partition_name, full_partition_name,
                     avb_hash_desc.partition_name_len) != 0) {
        continue;
      }

      desc_salt = desc_partition_name + avb_hash_desc.partition_name_len;
      desc_digest = desc_salt + avb_hash_desc.salt_len;
      if (avb_hash_desc.digest_len > sizeof(desc->digest) ||
          avb_hash_desc.salt_len > sizeof(desc->salt)) {
        ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT;
        goto out_with_buf;
      }

      desc->salt_len = avb_hash_desc.salt_len;
      desc->digest_len = avb_hash_desc.digest_len;
      desc->image_size = avb_hash_desc.image_size;
      memcpy(desc->salt, desc_salt, desc->salt_len);
      strlcpy((char*)desc->hash_algorithm,
              (char*)avb_hash_desc.hash_algorithm,
              sizeof(desc->hash_algorithm));
      memcpy(desc->digest, desc_digest, desc->digest_len);
      ret = AVB_SLOT_VERIFY_RESULT_OK;
      break;
    }
  }

out_with_buf:
  avb_free(vbmeta_buf);
out_with_ops:
  avb_ops_user_free(ops);
out:
  return ret;
}

void avb_hash_desc_dump(const struct avb_hash_desc_t* desc) {
  int i;

  avb_printf("%-16s : %" PRIu64 " bytes\n", "Image Size", desc->image_size);
  avb_printf("%-16s : %s\n", "Hash Algorithm", desc->hash_algorithm);
  avb_printf("%-16s : %" PRIu32 "\n", "Salt Length", desc->salt_len);
  avb_printf("%-16s : ", "Salt");
  for (i = 0; i < desc->salt_len; i++) {
    avb_printf("%02" PRIx8 "", desc->salt[i]);
  }
  avb_printf("\n");
  avb_printf("%-16s : %" PRIu32 "\n", "Digest Length", desc->digest_len);
  avb_printf("%-16s : ", "Digest");
  for (i = 0; i < desc->digest_len; i++) {
    avb_printf("%02" PRIx8 "", desc->digest[i]);
  }
  avb_printf("\n");
}
