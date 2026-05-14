#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstdlib>
#include <cstring>

/* ============================================================
 * X25519 — 基于 TweetNaCl 公域实现 (montgomery ladder)
 * https://tweetnacl.cr.yp.to/
 * ============================================================ */
typedef long long i64;
typedef unsigned char u8;
typedef i64 gf[16];

static const u8 BASE_9[32] = {9};

static void add(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}
static void sub(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}
static void sel(gf p, gf q, i64 b) {
    i64 t, c = ~(b-1);
    for (int i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t; q[i] ^= t;
    }
}
static void pack25519(u8 *o, const gf n) {
    gf t, m;
    for (int i = 0; i < 16; i++) t[i] = n[i];
    i64 carry;
    for (int i = 0; i < 15; i++) {
        carry = (t[i] + 128) >> 8;
        t[i] -= carry << 8;
        t[i+1] += carry;
    }
    carry = (t[15] + 128) >> 8; t[15] -= carry << 8;
    t[0] += 38 * carry;
    for (int i = 0; i < 15; i++) {
        carry = (t[i] + 128) >> 8;
        t[i] -= carry << 8;
        t[i+1] += carry;
    }
    carry = (t[15] + 128) >> 8; t[15] -= carry << 8;
    t[0] += 38 * carry;
    for (int i = 0; i < 16; i++) {
        o[2*i] = t[i] & 0xFF;
        o[2*i+1] = t[i] >> 8;
    }
}
static void unpack25519(gf o, const u8 *n) {
    for (int i = 0; i < 16; i++)
        o[i] = (i64)n[2*i] + ((i64)n[2*i+1] << 8);
    o[15] &= 0x7FFF;
}
static void mul(gf o, const gf a, const gf b) {
    i64 t[31] = {0};
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            t[i+j] += a[i] * b[j];
    for (int i = 0; i < 15; i++)
        t[i] += 38 * t[i+16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    i64 carry = 0;
    for (int i = 0; i < 16; i++) {
        o[i] += carry;
        carry = (o[i] + 128) >> 8;
        o[i] -= carry << 8;
    }
    o[0] += 38 * carry;
}
static void sqr(gf o, const gf a) { mul(o, a, a); }
static void inv(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; a++) c[a] = i[a];
    for (int a = 253; a >= 0; a--) {
        sqr(c, c);
        if (a != 2 && a != 4) mul(c, c, i);
    }
    for (int a = 0; a < 16; a++) o[a] = c[a];
}

static void x25519_core(u8 *r, const u8 *s, const u8 *p) {
    gf x1, x2, z2, x3, z3, A, B, C, D, E, AA, BB, DA, CB;
    u8 e[32]; memcpy(e, s, 32);
    e[0] &= 248; e[31] &= 127; e[31] |= 64;

    unpack25519(x1, p);
    memset(x2, 0, sizeof(x2)); memset(z2, 0, sizeof(z2));
    memset(x3, 0, sizeof(x3)); memset(z3, 0, sizeof(z3));
    x2[0] = z3[0] = 1;
    for (int i = 0; i < 16; i++) x3[i] = x1[i];

    int swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        int b = (e[pos/8] >> (pos%8)) & 1;
        sel(x2, x3, swap ^ b);
        sel(z2, z3, swap ^ b);
        swap = b;

        add(A, x2, z2); sqr(AA, A);
        sub(B, x2, z2); sqr(BB, B);
        sub(E, AA, BB);
        add(C, x3, z3);
        sub(D, x3, z3);
        mul(DA, D, A);
        mul(CB, C, B);
        gf DAsubCB;
        for (int i = 0; i < 16; i++) {
            x2[i] = AA[i] * BB[i];
            z2[i] = E[i] * (AA[i] + 121665 * E[i]);
            x3[i] = (DA[i] + CB[i]) * (DA[i] + CB[i]);
            DAsubCB[i] = DA[i] - CB[i];
        }
        mul(z3, DAsubCB, x1);
    }
    sel(x2, x3, swap); sel(z2, z3, swap);

    inv(z2, z2);
    for (int i = 0; i < 16; i++) x2[i] = x2[i] * z2[i];
    for (int i = 15; i > 0; i--) { x2[i-1] += 38 * (x2[i] >> 16); x2[i] &= 0xFFFF; }
    pack25519(r, x2);
}

/* ============================================================
 * AES (OpenSSL EVP)
 * ============================================================ */
extern "C" {

__declspec(dllexport) int __cdecl aes_256_gcm_encrypt(
    int pt, int pt_len, int key, int iv, int tag, int out
) {
    auto _pt  = (unsigned char*)(pt);
    auto _key = (unsigned char*)(key);
    auto _iv  = (unsigned char*)(iv);
    auto _tag = (unsigned char*)(tag);
    auto _out = (unsigned char*)(out);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0, len2 = 0;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), 0, 0, 0)) goto done;
    if (!EVP_EncryptInit_ex(ctx, 0, 0, _key, _iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, _out, &len, _pt, pt_len)) goto done;
    if (!EVP_EncryptFinal_ex(ctx, _out + len, &len2)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, _tag)) goto done;
    ret = len + len2;
done: EVP_CIPHER_CTX_free(ctx); return ret;
}

__declspec(dllexport) int __cdecl aes_256_gcm_decrypt(
    int ct, int ct_len, int key, int iv, int tag, int out
) {
    auto _ct  = (unsigned char*)(ct);
    auto _key = (unsigned char*)(key);
    auto _iv  = (unsigned char*)(iv);
    auto _tag = (unsigned char*)(tag);
    auto _out = (unsigned char*)(out);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0, len2 = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), 0, 0, 0)) goto done;
    if (!EVP_DecryptInit_ex(ctx, 0, 0, _key, _iv)) goto done;
    if (!EVP_DecryptUpdate(ctx, _out, &len, _ct, ct_len)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, _tag)) goto done;
    if (EVP_DecryptFinal_ex(ctx, _out + len, &len2) <= 0) goto done;
    ret = len + len2;
done: EVP_CIPHER_CTX_free(ctx); return ret;
}

__declspec(dllexport) int __cdecl aes_128_ctr_encrypt(int data, int data_len, int key, int iv, int out) {
    auto _data = (unsigned char*)(data);
    auto _key  = (unsigned char*)(key);
    auto _iv   = (unsigned char*)(iv);
    auto _out  = (unsigned char*)(out);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0, len2 = 0;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), 0, 0, 0)) goto done;
    if (!EVP_EncryptInit_ex(ctx, 0, 0, _key, _iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, _out, &len, _data, data_len)) goto done;
    if (!EVP_EncryptFinal_ex(ctx, _out + len, &len2)) goto done;
    ret = len + len2;
done: EVP_CIPHER_CTX_free(ctx); return ret;
}
__declspec(dllexport) int __cdecl aes_128_ctr_decrypt(int data, int data_len, int key, int iv, int out) {
    return aes_128_ctr_encrypt(data, data_len, key, iv, out);
}

/* ---- X25519（纯 C，无 OpenSSL 依赖） ---- */

__declspec(dllexport) int __cdecl x25519_keypair(int out_pub, int out_priv) {
    auto pub  = (unsigned char*)(out_pub);
    auto priv = (unsigned char*)(out_priv);
    if (RAND_bytes(priv, 32) != 1) return 0;
    priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;
    x25519_core(pub, priv, BASE_9);
    return 1;
}

__declspec(dllexport) int __cdecl x25519_shared_secret(int out_shared, int priv, int pub) {
    auto shared = (unsigned char*)(out_shared);
    auto _priv  = (const unsigned char*)(priv);
    auto _pub   = (const unsigned char*)(pub);
    x25519_core(shared, _priv, _pub);
    int z = 0;
    for (int i = 0; i < 32; i++) z |= shared[i];
    return z ? 1 : 0;
}

} // extern "C"
