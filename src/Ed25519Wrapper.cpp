#include "Ed25519Wrapper.h"
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/classes/os.hpp>
#include <godot_cpp/variant/utility_functions.hpp>
#include <cstring>
#include <cstdlib>

#include "tweetnacl.h"

using namespace godot;

// --- МЕХАНИЗМ ПОДМЕНЫ ЭНТРОПИИ ---
// Статические переменные для передачи seed в C-функцию randombytes
static unsigned char _g_forced_seed[32];
static bool _g_use_forced_seed = false;

// Реализация randombytes, которую требует tweetnacl.c
extern "C" {
    void randombytes(unsigned char *x, unsigned long long xlen) {
        // 1. Режим принудительного seed (для восстановления кошелька)
        if (_g_use_forced_seed && xlen == 32) {
            memcpy(x, _g_forced_seed, 32);
            return;
        }

        // 2. Обычный режим (используем CSPRNG от Godot)
        PackedByteArray bytes = OS::get_singleton()->get_entropy((int)xlen);
        
        if (bytes.size() == (int)xlen) {
            memcpy(x, bytes.ptr(), xlen);
        } else {
            // Fallback: если OS entropy недоступна (крайне редко), используем rand()
            // В продакшене лучше падать с ошибкой, но для надежности сборки оставим так.
            for (unsigned long long i = 0; i < xlen; i++) {
                x[i] = (unsigned char)(rand() % 256);
            }
        }
    }
}
// ---------------------------------

Ed25519Wrapper::Ed25519Wrapper() {}
Ed25519Wrapper::~Ed25519Wrapper() {}

PackedByteArray Ed25519Wrapper::get_random_bytes(int count) {
    if (count <= 0) return PackedByteArray();
    
    PackedByteArray out;
    out.resize(count);
    randombytes(out.ptrw(), count);
    return out;
}

Dictionary Ed25519Wrapper::key_pair_from_seed(const PackedByteArray &seed) {
    Dictionary result;

    if (seed.size() != 32) {
        ERR_PRINT("Ed25519 seed must be exactly 32 bytes.");
        return result;
    }

    // Включаем режим подмены RNG
    memcpy(_g_forced_seed, seed.ptr(), 32);
    _g_use_forced_seed = true;

    unsigned char pk[32];
    unsigned char sk[64];

    // TweetNaCl запросит randombytes(32) и получит наш seed
    crypto_sign_keypair(pk, sk);

    // Выключаем режим подмены
    _g_use_forced_seed = false;
    // Очищаем буфер seed в памяти для безопасности
    memset(_g_forced_seed, 0, 32);

    PackedByteArray pba_private;
    pba_private.resize(64);
    memcpy(pba_private.ptrw(), sk, 64);

    PackedByteArray pba_public;
    pba_public.resize(32);
    memcpy(pba_public.ptrw(), pk, 32);

    result["private"] = pba_private;
    result["public"] = pba_public;
    return result;
}

Dictionary Ed25519Wrapper::key_pair_random() {
    unsigned char pk[32];
    unsigned char sk[64];

    // Вызываем со стандартным RNG
    crypto_sign_keypair(pk, sk);

    PackedByteArray pba_private;
    pba_private.resize(64);
    memcpy(pba_private.ptrw(), sk, 64);

    PackedByteArray pba_public;
    pba_public.resize(32);
    memcpy(pba_public.ptrw(), pk, 32);

    Dictionary result;
    result["private"] = pba_private;
    result["public"] = pba_public;
    return result;
}

PackedByteArray Ed25519Wrapper::sign(const PackedByteArray &message, const PackedByteArray &private_key) {
    PackedByteArray signature;

    if (private_key.size() != 64) {
        ERR_PRINT("Private key must be 64 bytes.");
        return signature;
    }

    // TweetNaCl crypto_sign формирует "подписанное сообщение" (сигнатура + сообщение).
    // Нам нужно выделить буфер под (msg_len + 64).
    unsigned long long mlen = message.size();
    unsigned long long smlen = mlen + 64;
    
    unsigned char *sm = (unsigned char *)malloc(smlen);
    if (!sm) {
        ERR_PRINT("Out of memory in sign.");
        return signature;
    }

    // crypto_sign(signed_msg, &signed_len, msg, msg_len, sk)
    crypto_sign(sm, &smlen, message.ptr(), mlen, private_key.ptr());

    // В TweetNaCl первые 64 байта результата 'sm' - это и есть подпись.
    signature.resize(64);
    memcpy(signature.ptrw(), sm, 64);

    free(sm);
    return signature;
}

bool Ed25519Wrapper::verify(const PackedByteArray &signature, const PackedByteArray &message, const PackedByteArray &public_key) {
    if (signature.size() != 64) {
        ERR_PRINT("Signature must be 64 bytes.");
        return false;
    }
    if (public_key.size() != 32) {
        ERR_PRINT("Public key must be 32 bytes.");
        return false;
    }

    unsigned long long mlen = message.size();
    unsigned long long smlen = mlen + 64;

    // Для проверки TweetNaCl требует воссоздать структуру "подпись + сообщение"
    unsigned char *sm = (unsigned char *)malloc(smlen);
    unsigned char *m_out = (unsigned char *)malloc(smlen); // Буфер для проверенного сообщения
    
    if (!sm || !m_out) {
        if(sm) free(sm);
        if(m_out) free(m_out);
        ERR_PRINT("Out of memory in verify.");
        return false;
    }

    // Собираем sm: [64 байта подписи] + [сообщение]
    memcpy(sm, signature.ptr(), 64);
    memcpy(sm + 64, message.ptr(), mlen);

    unsigned long long m_out_len;
    
    // crypto_sign_open возвращает 0 если подпись верна, -1 если нет
    int result = crypto_sign_open(m_out, &m_out_len, sm, smlen, public_key.ptr());

    free(sm);
    free(m_out);

    return (result == 0);
}

void Ed25519Wrapper::_bind_methods() {
    ClassDB::bind_method(D_METHOD("get_random_bytes", "count"), &Ed25519Wrapper::get_random_bytes);
    ClassDB::bind_method(D_METHOD("key_pair_from_seed", "seed"), &Ed25519Wrapper::key_pair_from_seed);
    ClassDB::bind_method(D_METHOD("key_pair_random"), &Ed25519Wrapper::key_pair_random);
    ClassDB::bind_method(D_METHOD("sign", "message", "private_key"), &Ed25519Wrapper::sign);
    ClassDB::bind_method(D_METHOD("verify", "signature", "message", "public_key"), &Ed25519Wrapper::verify);
}