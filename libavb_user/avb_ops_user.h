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

#ifndef AVB_OPS_USER_H_
#define AVB_OPS_USER_H_

#include <libavb/libavb.h>

#ifdef __cplusplus
extern "C" {
#endif

struct avb_ops_user_data_t {
  const char* key;
  const char* vbmeta;
};

/* Allocates an AvbOps instance suitable for use in userspace
 * on the device. Returns NULL on OOM.
 *
 * The returned AvbOps has the following characteristics:
 *
 * - The read_from_partition(), write_to_partition(),
 *   get_size_of_partition() and validate_vbmeta_public_key()
 *   operations are implemented *
 *
 * - The remaining operations are implemented and never fails and
 *   return the following values:
 *   - read_rollback_index(): returns 0 for any roolback index.
 *   - write_rollback_index(): no-op.
 *   - read_is_device_unlocked(): always returns |true|.
 *   - read_persistent_value():  no-op.
 *   - write_persistent_value(): no-op.
 *   - get_unique_guid_for_partition(): always returns the empty string.
 * Free with avb_ops_user_free().
 */
AvbOps* avb_ops_user_new(void);

/* Frees an AvbOps instance previously allocated with avb_ops_device_new(). */
void avb_ops_user_free(AvbOps* ops);

#ifdef __cplusplus
}
#endif

#endif /* AVB_OPS_USER_H_ */
