#include <openssl/evp.h>

/*
 * aes_gcm_decrypt(key, key_len, iv, iv_len, ct, ct_len, tag, tag_len)
 * 参数均为整数(指针地址和长度)
 * 返回明文长度, 负数=失败
 */
__declspec(dllexport) int aes_gcm_decrypt(
    int key, int key_len,
    int iv,  int iv_len,
    int ct,  int ct_len,
    int tag, int tag_len
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1, len = 0, len2 = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, (void*)key, (void*)iv)) goto done;
    if (!EVP_DecryptUpdate(ctx, (void*)ct, &len, (void*)ct, ct_len)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag)) goto done;
    if (EVP_DecryptFinal_ex(ctx, (unsigned char*)ct + len, &len2) != 1) goto done;

    ret = len + len2;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * aes_gcm_encrypt(key, key_len, iv, iv_len, pt, pt_len, tag, tag_len)
 * 参数均为整数(指针地址和长度)
 * 返回密文长度, 负数=失败
 */
__declspec(dllexport) int aes_gcm_encrypt(
    int key, int key_len,
    int iv,  int iv_len,
    int pt,  int pt_len,
    int tag, int tag_len
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1, len = 0, len2 = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, (void*)key, (void*)iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, (void*)pt, &len, (void*)pt, pt_len)) goto done;
    if (!EVP_EncryptFinal_ex(ctx, (unsigned char*)pt + len, &len2)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, (void*)tag)) goto done;

    ret = len + len2;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
