#include <openssl/evp.h>

// 返回明文长度，失败返回负数
__declspec(dllexport) int aes_gcm_decrypt(
    const unsigned char* key, int key_len,
    const unsigned char* iv,  int iv_len,
    const unsigned char* ct,  int ct_len,
    const unsigned char* tag, int tag_len,
    unsigned char* out,       int out_max
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1, len = 0, len2 = 0;

    if (key_len == 16)
        { if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) goto done; }
    else if (key_len == 32)
        { if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done; }
    else goto done;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_DecryptUpdate(ctx, out, &len, ct, ct_len)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag)) goto done;
    if (EVP_DecryptFinal_ex(ctx, out + len, &len2) != 1) goto done;

    ret = len + len2;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// 返回密文长度，失败返回负数
__declspec(dllexport) int aes_gcm_encrypt(
    const unsigned char* key, int key_len,
    const unsigned char* iv,  int iv_len,
    const unsigned char* pt,  int pt_len,
    unsigned char* ct,        int ct_max,
    unsigned char* tag,       int tag_max
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1, len = 0, len2 = 0;

    if (key_len == 16)
        { if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) goto done; }
    else if (key_len == 32)
        { if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done; }
    else goto done;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len)) goto done;
    if (!EVP_EncryptFinal_ex(ctx, ct + len, &len2)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_max, tag)) goto done;

    ret = len + len2;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
