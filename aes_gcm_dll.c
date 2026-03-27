#include <openssl/evp.h>

static int bs_len(const unsigned char *p) { return *(int *)(p - 4); }

__declspec(dllexport) int aes_gcm_decrypt(
    const unsigned char* key, const unsigned char* iv,
    unsigned char* ct, const unsigned char* tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0, len2 = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, bs_len(iv), NULL)) goto done;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_DecryptUpdate(ctx, ct, &len, ct, bs_len(ct))) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, bs_len(tag), (void*)tag)) goto done;
    if (EVP_DecryptFinal_ex(ctx, ct + len, &len2) != 1) goto done;
    ret = len + len2;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

__declspec(dllexport) int aes_gcm_encrypt(
    const unsigned char* key, const unsigned char* iv,
    unsigned char* pt, unsigned char* tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0, len2 = 0;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, bs_len(iv), NULL)) goto done;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, pt, &len, pt, bs_len(pt))) goto done;
    if (!EVP_EncryptFinal_ex(ctx, pt + len, &len2)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, bs_len(tag), tag)) goto done;
    ret = len + len2;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
