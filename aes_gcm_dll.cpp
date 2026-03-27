#include <openssl/evp.h>
#include <cstdlib>
#include <cstring>

extern "C" {

/* AES-256-GCM 加密
 * pt/pt_len=明文, key=32字节, iv=12字节, tag=16字节输出buffer, out=密文输出buffer
 * 返回: 密文长度, 负数=失败 */
__declspec(dllexport) int __cdecl aes_gcm_encrypt(
    int pt, int pt_len,
    int key, int iv, int tag, int out
) {
    auto _pt  = reinterpret_cast<unsigned char*>(pt);
    auto _key = reinterpret_cast<unsigned char*>(key);
    auto _iv  = reinterpret_cast<unsigned char*>(iv);
    auto _tag = reinterpret_cast<unsigned char*>(tag);
    auto _out = reinterpret_cast<unsigned char*>(out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1, len = 0, len2 = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) goto done;
    if (!EVP_EncryptInit_ex(ctx, nullptr, nullptr, _key, _iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, _out, &len, _pt, pt_len)) goto done;
    if (!EVP_EncryptFinal_ex(ctx, _out + len, &len2)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, _tag)) goto done;

    ret = len + len2;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* AES-256-GCM 解密
 * ct/ct_len=密文长度, key=32字节, iv=12字节, tag=16字节
 * out写入: 明文
 * 返回: 明文长度, 负数=失败 */
__declspec(dllexport) int __cdecl aes_gcm_decrypt(
    int ct, int ct_len,
    int key, int iv, int tag, int out
) {
    auto _ct  = reinterpret_cast<unsigned char*>(ct);
    auto _key = reinterpret_cast<unsigned char*>(key);
    auto _iv  = reinterpret_cast<unsigned char*>(iv);
    auto _tag = reinterpret_cast<unsigned char*>(tag);
    auto _out = reinterpret_cast<unsigned char*>(out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1, len = 0, len2 = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) goto done;
    if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, _key, _iv)) goto done;
    if (!EVP_DecryptUpdate(ctx, _out, &len, _ct, ct_len)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, _tag)) goto done;
    if (EVP_DecryptFinal_ex(ctx, _out + len, &len2) != 1) goto done;

    ret = len + len2;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

} // extern "C"
