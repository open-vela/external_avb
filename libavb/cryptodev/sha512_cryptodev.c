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

#include <libavb/avb_sha.h>
#include <libavb/avb_util.h>

void avb_sha512_init(AvbSHA512Ctx* avb_ctx) {
    avb_cryptodev_context_t* ctx = (avb_cryptodev_context_t*)avb_ctx->reserved;
    avb_assert(avb_cryptodev_init(ctx) == 0);
    ctx->session.mac = CRYPTO_SHA2_512;
    avb_assert(avb_cryptodev_get_session(ctx) == 0);
}

void avb_sha512_update(AvbSHA512Ctx* avb_ctx, const uint8_t* data, size_t len) {
    avb_cryptodev_context_t* ctx = (avb_cryptodev_context_t*)avb_ctx->reserved;
    ctx->crypt.op = COP_ENCRYPT;
    ctx->crypt.flags |= COP_FLAG_UPDATE;
    ctx->crypt.src = (caddr_t)data;
    ctx->crypt.len = len;
    avb_assert(avb_cryptodev_crypt(ctx) == 0);
}

uint8_t* avb_sha512_final(AvbSHA512Ctx* avb_ctx) {
    avb_cryptodev_context_t* ctx = (avb_cryptodev_context_t*)avb_ctx->reserved;
    ctx->crypt.op = COP_ENCRYPT;
    ctx->crypt.flags = 0;
    ctx->crypt.mac = (caddr_t)avb_ctx->buf;
    avb_assert(avb_cryptodev_crypt(ctx) == 0);
    avb_cryptodev_free_session(ctx);
    avb_cryptodev_free(ctx);
    return avb_ctx->buf;
}
