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
  int ret;
  int n;

  if (params == NULL || params->key == NULL || params->partition == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT;
    goto out;
  }

  ops = avb_ops_user_new();
  if (ops == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out;
  }

  const char* partitions[][2] = {
      {params->partition, NULL},
      {params->image, NULL},
  };

  ops->user_data = (char*)params->key;

  for (n = 0; n < 2; n++) {
    ret = avb_slot_verify(ops,
                          partitions[n],
                          params->suffix ? params->suffix : "",
                          AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION,
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
  AvbOps* ops;
  AvbFooter footer;
  size_t vbmeta_num_read;
  uint8_t* vbmeta_buf = NULL;
  size_t num_descriptors;
  const AvbDescriptor** descriptors;
  AvbDescriptor avb_desc;
  int ret;

  if (full_partition_name == NULL || desc == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT;
    goto out;
  }

  ops = avb_ops_user_new();
  if (ops == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out;
  }

  ret = avb_footer(ops, full_partition_name, &footer);
  if (ret != AVB_IO_RESULT_OK) {
    avb_error("Loading footer failed: ", full_partition_name);
    goto out_with_ops;
  }

  vbmeta_buf = avb_malloc(footer.vbmeta_size);
  if (vbmeta_buf == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out_with_ops;
  }

  ret = ops->read_from_partition(ops,
                                 full_partition_name,
                                 footer.vbmeta_offset,
                                 footer.vbmeta_size,
                                 vbmeta_buf,
                                 &vbmeta_num_read);
  if (ret != AVB_IO_RESULT_OK) {
    goto out_with_ops;
  }

  AvbVBMetaImageHeader vbmeta_header;
  avb_vbmeta_image_header_to_host_byte_order((AvbVBMetaImageHeader*)vbmeta_buf,
                                             &vbmeta_header);

  descriptors =
      avb_descriptor_get_all(vbmeta_buf, vbmeta_num_read, &num_descriptors);
  if (!avb_descriptor_validate_and_byteswap(descriptors[0], &avb_desc)) {
    avb_error(full_partition_name, ": Descriptor is invalid.\n");
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
    goto out_with_ops;
  }

  switch (avb_desc.tag) {
    case AVB_DESCRIPTOR_TAG_HASH: {
      AvbHashDescriptor avb_hash_desc;
      const AvbDescriptor* descriptor = descriptors[0];
      const uint8_t* desc_partition_name = NULL;
      const uint8_t* desc_salt;
      const uint8_t* desc_digest;

      if (!avb_hash_descriptor_validate_and_byteswap(
              (const AvbHashDescriptor*)descriptor, &avb_hash_desc)) {
        ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
        goto out_with_ops;
      }
      desc_partition_name =
          ((const uint8_t*)descriptor) + sizeof(AvbHashDescriptor);
      desc_salt = desc_partition_name + avb_hash_desc.partition_name_len;
      desc_digest = desc_salt + avb_hash_desc.salt_len;
      if (avb_hash_desc.digest_len > sizeof(desc->digest)) {
        ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT;
        goto out_with_ops;
      }

      desc->digest_len = avb_hash_desc.digest_len;
      desc->image_size = avb_hash_desc.image_size;
      strlcpy((char*)desc->hash_algorithm,
              (char*)avb_hash_desc.hash_algorithm,
              sizeof(desc->hash_algorithm));
      memcpy(desc->digest, desc_digest, desc->digest_len);
      break;
    }

    default:
      ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
      break;
  }

out_with_ops:
  avb_ops_user_free(ops);
out:
  if (vbmeta_buf) avb_free(vbmeta_buf);
  return ret;
}

void avb_hash_desc_dump(const struct avb_hash_desc_t* desc) {
  int i;

  avb_printf("%-16s : %" PRIu64 " bytes\n", "Image Size", desc->image_size);
  avb_printf("%-16s : %s\n", "Hash Algorithm", desc->hash_algorithm);
  avb_printf("%-16s : %" PRIu32 "\n", "Digest Length", desc->digest_len);
  avb_printf("%-16s : ", "Digest");
  for (i = 0; i < desc->digest_len; i++) {
    avb_printf("%02" PRIx8 "", desc->digest[i]);
  }
  avb_printf("\n");
}
