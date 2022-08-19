/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2022 Christer Weinigel, Netnod <wingel@netnod.se>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>

#include "py/runtime.h"
#include "py/binary.h"
#include "py/mperrno.h"

// This is abit ugly, where can I find sodium.h?
int crypto_sign_open(unsigned char *m, unsigned long long *mlen_p,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#if MICROPY_PY_UED25519

#warning foo

STATIC mp_obj_t mod_ued25519_open(mp_obj_t signature_and_message,
                                  mp_obj_t public_key) {
    mp_buffer_info_t sm_bufinfo;
    mp_get_buffer_raise(signature_and_message, &sm_bufinfo, MP_BUFFER_READ);

    if (sm_bufinfo.len < 64) {
        mp_raise_ValueError("signature-and-message must be at least 64 bytes long");
    }

    mp_buffer_info_t pk_bufinfo;
    mp_get_buffer_raise(public_key, &pk_bufinfo, MP_BUFFER_READ);
    if (pk_bufinfo.len != 32) {
        mp_raise_ValueError("public verifying keys must be 32 bytes long");
    }

    vstr_t vstr;
    vstr_init_len(&vstr, sm_bufinfo.len - 64);
    unsigned char *out_buf = (unsigned char *)vstr.buf;
    unsigned long long out_len;

    int r = crypto_sign_open(out_buf, &out_len,
                             sm_bufinfo.buf, sm_bufinfo.len,
                             pk_bufinfo.buf);
    if (r) {
        vstr_clear(&vstr);
        return mp_const_none;
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

MP_DEFINE_CONST_FUN_OBJ_2(mod_ued25519_open_obj, mod_ued25519_open);

STATIC const mp_rom_map_elem_t mp_module_ued25519_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ued25519) },
    { MP_ROM_QSTR(MP_QSTR_open), MP_ROM_PTR(&mod_ued25519_open_obj) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_ued25519_globals, mp_module_ued25519_globals_table);

const mp_obj_module_t mp_module_ued25519 = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_ued25519_globals,
};

#endif // MICROPY_PY_UED25519
