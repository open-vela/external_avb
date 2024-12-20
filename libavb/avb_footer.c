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

#include "avb_footer.h"

#include "avb_util.h"
#include "avb_vbmeta_image.h"

bool avb_footer_validate_and_byteswap(const AvbFooter* src, AvbFooter* dest) {
  avb_memcpy(dest, src, sizeof(AvbFooter));

  dest->version_major = avb_be32toh(dest->version_major);
  dest->version_minor = avb_be32toh(dest->version_minor);

  dest->original_image_size = avb_be64toh(dest->original_image_size);
  dest->vbmeta_offset = avb_be64toh(dest->vbmeta_offset);
  dest->vbmeta_size = avb_be64toh(dest->vbmeta_size);

  /* Check that magic is correct. */
  if (avb_safe_memcmp(dest->magic, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) !=
      0) {
    avb_error("Footer magic is incorrect.\n");
    return false;
  }

  /* Ensure we don't attempt to access any fields if the footer major
   * version is not supported.
   */
  if (dest->version_major > AVB_FOOTER_VERSION_MAJOR) {
    avb_error("No support for footer version.\n");
    return false;
  }

  return true;
}

AvbIOResult avb_footer(AvbOps* ops,
                       const char* full_partition_name,
                       AvbFooter* footer) {
  uint8_t footer_buf[AVB_FOOTER_SIZE];
  size_t footer_num_read;
  int64_t read_offset = AVB_FOOTER_SEARCH_BLKSIZE
                            ? (AVB_FOOTER_SEARCH_BLKSIZE - AVB_FOOTER_SIZE)
                            : -AVB_FOOTER_SIZE;

  do {
    AvbIOResult io_ret = ops->read_from_partition(ops,
                                                  full_partition_name,
                                                  read_offset,
                                                  AVB_FOOTER_SIZE,
                                                  footer_buf,
                                                  &footer_num_read);
    if (io_ret != AVB_IO_RESULT_OK) {
      avb_error(full_partition_name, ": Error loading footer.\n");
      avb_printf("io_ret: %d\n", io_ret);
      return io_ret;
    }
    avb_assert(footer_num_read == AVB_FOOTER_SIZE);

    read_offset += AVB_FOOTER_SEARCH_BLKSIZE;
  } while ((AVB_FOOTER_SEARCH_BLKSIZE != 0) &&
           (avb_safe_memcmp(
                footer_buf, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) != 0));

  if (!avb_footer_validate_and_byteswap((const AvbFooter*)footer_buf, footer)) {
    avb_error(full_partition_name, ": No footer detected.\n");
  } else {
    /* Basic footer sanity check since the data is untrusted. */
    if (footer->vbmeta_size > VBMETA_MAX_SIZE) {
      avb_error(full_partition_name, ": Invalid vbmeta size in footer.\n");
    } else {
      return AVB_IO_RESULT_OK;
    }
  }

  return AVB_IO_RESULT_ERROR_IO;
}
