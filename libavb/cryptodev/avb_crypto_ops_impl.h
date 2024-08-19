/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef AVB_CRYPTO_OPS_IMPL_H_
#define AVB_CRYPTO_OPS_IMPL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <crypto/cryptodev.h>

typedef struct avb_cryptodev_context_s {
  int fd;
  struct session_op session;
  struct crypt_op crypt;
  struct crypt_kop cryptk;
} avb_cryptodev_context_t;

#define AVB_SHA256_CONTEXT_SIZE sizeof(avb_cryptodev_context_t)
#define AVB_SHA512_CONTEXT_SIZE sizeof(avb_cryptodev_context_t)
#define AVB_CRC32_CONTEXT_SIZE  sizeof(avb_cryptodev_context_t)

static inline int avb_cryptodev_init(avb_cryptodev_context_t *ctx) {
  int ret;
  int fd;

  memset(ctx, 0, sizeof(avb_cryptodev_context_t));
  fd = open("/dev/crypto", O_RDWR, 0);
  if (fd < 0) {
    return -errno;
  }

  ret = ioctl(fd, CRIOGET, &ctx->fd);
  close(fd);
  if (ret < 0) {
    ret = -errno;
  }

  return ret;
}

static inline void avb_cryptodev_free(avb_cryptodev_context_t *ctx) {
  close(ctx->fd);
  memset(ctx, 0, sizeof(avb_cryptodev_context_t));
}

static inline int avb_cryptodev_get_session(avb_cryptodev_context_t *ctx) {
  int ret;

  ret = ioctl(ctx->fd, CIOCGSESSION, &ctx->session);
  if (ret < 0) {
    return -errno;
  }

  ctx->crypt.ses = ctx->session.ses;
  return ret;
}

static inline void avb_cryptodev_free_session(avb_cryptodev_context_t *ctx) {
  ioctl(ctx->fd, CIOCFSESSION, &ctx->session.ses);
  ctx->crypt.ses = 0;
}

static inline int avb_cryptodev_crypt(avb_cryptodev_context_t *ctx) {
  int ret;

  ret = ioctl(ctx->fd, CIOCCRYPT, &ctx->crypt);
  return ret < 0 ? -errno : ret;
}

static inline int avb_cryptodev_cryptk(avb_cryptodev_context_t *ctx) {
  int ret;

  ret = ioctl(ctx->fd, CIOCKEY, &ctx->cryptk);
  return ret < 0 ? -errno : ret;
}

#ifdef __cplusplus
}
#endif

#endif /* AVB_CRYPTO_OPS_IMPL_H_ */
