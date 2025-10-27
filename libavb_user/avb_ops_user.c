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

#include "avb_ops_user.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static void dump_buffer(const char* msg,
                        const uint8_t* buffer,
                        size_t num_bytes) {
  size_t i;

  if (msg) {
    avb_printf("%s (%p):\n", msg, buffer);
  }

  for (i = 0; i < num_bytes; i++) {
    if (i % 16 == 0) {
      if (i != 0) {
        avb_printf("\n");
      }
      avb_printf("%04zx: ", i);
    }
    avb_printf("%02" PRIx8 " ", buffer[i]);
  }
  avb_printf("\n");
}

static AvbIOResult read_from_partition(AvbOps* ops,
                                       const char* partition,
                                       int64_t offset,
                                       size_t num_bytes,
                                       void* buffer,
                                       size_t* out_num_read) {
  size_t nread = 0;
  int fd;

  fd = open(partition, O_RDONLY);
  if (fd < 0) return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;

  offset = lseek(fd, offset, offset >= 0 ? SEEK_SET : SEEK_END);
  if (offset < 0) {
    close(fd);
    return AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;
  }

  while (num_bytes > 0) {
    ssize_t ret = read(fd, buffer, num_bytes);
    if (ret > 0) {
      nread += ret;
      buffer += ret;
      num_bytes -= ret;
    } else if (ret == 0 || errno != EINTR)
      break;
  }

  close(fd);
  if (num_bytes && nread == 0) return AVB_IO_RESULT_ERROR_IO;

  *out_num_read = nread;
  return AVB_IO_RESULT_OK;
}

static AvbIOResult get_preloaded_partition(AvbOps* ops,
                                           const char* partition,
                                           size_t num_bytes,
                                           uint8_t** out_pointer,
                                           size_t* out_num_bytes_preloaded) {
  int fd;

  fd = open(partition, O_RDONLY);
  if (fd < 0) return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;

  if (ioctl(fd, BIOC_XIPBASE, (uintptr_t)out_pointer) < 0) *out_pointer = NULL;

  close(fd);

  *out_num_bytes_preloaded = *out_pointer ? num_bytes : 0;
  return AVB_IO_RESULT_OK;
}

static AvbIOResult write_to_partition(AvbOps* ops,
                                      const char* partition,
                                      int64_t offset,
                                      size_t num_bytes,
                                      const void* buffer) {
  int fd;

  fd = open(partition, O_WRONLY, 0660);
  if (fd < 0) return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;

  offset = lseek(fd, offset, offset >= 0 ? SEEK_SET : SEEK_END);
  if (offset < 0) {
    close(fd);
    return AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;
  }

  while (num_bytes > 0) {
    ssize_t ret = write(fd, buffer, num_bytes);
    if (ret > 0) {
      buffer += ret;
      num_bytes -= ret;
    } else if (ret == 0 || errno != EINTR)
      break;
  }

  close(fd);
  if (num_bytes) return AVB_IO_RESULT_ERROR_IO;

  return AVB_IO_RESULT_OK;
}

static AvbIOResult validate_vbmeta_public_key(
    AvbOps* ops,
    const uint8_t* public_key_data,
    size_t public_key_length,
    const uint8_t* public_key_metadata,
    size_t public_key_metadata_length,
    bool* out_is_trusted) {
  return ops->validate_public_key_for_partition(ops,
                                                "vbmeta",
                                                public_key_data,
                                                public_key_length,
                                                public_key_metadata,
                                                public_key_metadata_length,
                                                out_is_trusted,
                                                NULL);
}

static AvbIOResult read_rollback_index(AvbOps* ops,
                                       size_t rollback_index_location,
                                       uint64_t* out_rollback_index) {
  *out_rollback_index = 0;
  return AVB_IO_RESULT_OK;
}

static AvbIOResult read_is_device_unlocked(AvbOps* ops, bool* out_is_unlocked) {
  *out_is_unlocked = false;
  return AVB_IO_RESULT_OK;
}

static AvbIOResult get_unique_guid_for_partition(AvbOps* ops,
                                                 const char* partition,
                                                 char* guid_buf,
                                                 size_t guid_buf_size) {
  memset(guid_buf, 0, guid_buf_size);
  strlcpy(guid_buf, partition, guid_buf_size);
  return AVB_IO_RESULT_OK;
}

static AvbIOResult get_size_of_partition(AvbOps* ops,
                                         const char* partition,
                                         uint64_t* out_size_num_bytes) {
  struct stat buf;

  if (stat(partition, &buf) < 0) return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;

  *out_size_num_bytes = buf.st_size;
  return AVB_IO_RESULT_OK;
}

static AvbIOResult validate_public_key_for_partition(
    AvbOps* ops,
    const char* partition,
    const uint8_t* public_key_data,
    size_t public_key_length,
    const uint8_t* public_key_metadata,
    size_t public_key_metadata_length,
    bool* out_is_trusted,
    uint32_t* out_rollback_index_location) {
  AvbIOResult result;
  uint8_t* key_data;
  size_t key_length;
  struct avb_ops_user_data_t* user_data = (struct avb_ops_user_data_t*)ops->user_data;

  if (user_data == NULL) return AVB_IO_RESULT_ERROR_INVALID_VALUE_SIZE;

  key_data = avb_malloc(public_key_length);
  if (key_data == NULL) return AVB_IO_RESULT_ERROR_OOM;

  result = ops->read_from_partition(
      ops, user_data->key, 0, public_key_length, key_data, &key_length);
  if (result == AVB_IO_RESULT_OK) {
    *out_is_trusted = memcmp(key_data, public_key_data, public_key_length) == 0;
    if (!*out_is_trusted) {
      dump_buffer("pub_key", key_data, key_length);
      dump_buffer("vbmeta pub_key", public_key_data, public_key_length);
    }
  }

  free(key_data);
  return result;
}

static AvbIOResult vbmeta_partiton_name(AvbOps* ops, const char** out_vbmeta_name) {
  struct avb_ops_user_data_t* user_data = (struct avb_ops_user_data_t*)ops->user_data;
  if (user_data && user_data->vbmeta) {
    *out_vbmeta_name = user_data->vbmeta;
    return AVB_IO_RESULT_OK;
  }

  return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
}

AvbOps* avb_ops_user_new() {
  AvbOps* ops;

  ops = avb_malloc(sizeof(AvbOps));
  if (ops == NULL) {
    avb_error("Error allocating memory for AvbOps.\n");
    goto out;
  }

  ops->user_data = NULL;
  ops->ab_ops = NULL;
  ops->atx_ops = NULL;
  ops->read_from_partition = read_from_partition;
  ops->get_preloaded_partition = get_preloaded_partition;
  ops->write_to_partition = write_to_partition;
  ops->validate_vbmeta_public_key = validate_vbmeta_public_key;
  ops->read_rollback_index = read_rollback_index;
  ops->write_rollback_index = NULL;
  ops->read_is_device_unlocked = read_is_device_unlocked;
  ops->get_unique_guid_for_partition = get_unique_guid_for_partition;
  ops->read_persistent_value = NULL;
  ops->write_persistent_value = NULL;
  ops->get_size_of_partition = get_size_of_partition;
  ops->validate_public_key_for_partition = validate_public_key_for_partition;
  ops->vbmeta_partiton_name = vbmeta_partiton_name;

out:
  return ops;
}

void avb_ops_user_free(AvbOps* ops) {
  free(ops);
}