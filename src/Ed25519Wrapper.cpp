#include "Ed25519Wrapper.h"
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/classes/os.hpp>
#include <godot_cpp/variant/utility_functions.hpp>
#include <cstring>
#include <cstdlib> // Здесь живет std::free

#include "tweetnacl.h"

using namespace godot;

// --- МЕХАНИЗМ ПОДМЕНЫ ЭНТРОПИИ ---
static unsigned char _g_forced_seed[32];
static bool _g_use_forced_seed = false;

extern "C" {
    void randombytes(unsigned char *x, unsigned long long xlen) {
        if (_g_use_forced_seed && xlen == 32) {
            memcpy(x, _g_forced_seed, 32);
            return;
        }

        PackedByteArray bytes = OS::get_singleton()->get_entropy((int)xlen);
        
        if (bytes.size() == (int)xlen) {
            memcpy(x, bytes.ptr(), xlen);
        } else {
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

    memcpy(_g_forced_seed, seed.ptr(), 32);
    _g_use_forced_seed = true;

    unsigned char pk[32];
    unsigned char sk[64];

    crypto_sign_keypair(pk, sk);

    _g_use_forced_seed = false;
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

    unsigned long long mlen = message.size();
    unsigned long long smlen = mlen + 64;
    
    unsigned char *sm = (unsigned char *)std::malloc(smlen); // Используем std::malloc
    if (!sm) {
        ERR_PRINT("Out of memory in sign.");
        return signature;
    }

    crypto_sign(sm, &smlen, message.ptr(), mlen, private_key.ptr());

    signature.resize(64);
    memcpy(signature.ptrw(), sm, 64);

    std::free(sm); // ИСПРАВЛЕНО: std::free вместо free
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

    unsigned char *sm = (unsigned char *)std::malloc(smlen);
    unsigned char *m_out = (unsigned char *)std::malloc(smlen);
    
    if (!sm || !m_out) {
        if(sm) std::free(sm);       // ИСПРАВЛЕНО: std::free
        if(m_out) std::free(m_out); // ИСПРАВЛЕНО: std::free
        ERR_PRINT("Out of memory in verify.");
        return false;
    }

    memcpy(sm, signature.ptr(), 64);
    memcpy(sm + 64, message.ptr(), mlen);

    unsigned long long m_out_len;
    
    int result = crypto_sign_open(m_out, &m_out_len, sm, smlen, public_key.ptr());

    std::free(sm);    // ИСПРАВЛЕНО: std::free
    std::free(m_out); // ИСПРАВЛЕНО: std::free

    return (result == 0);
}

void Ed25519Wrapper::_bind_methods() {
    ClassDB::bind_method(D_METHOD("get_random_bytes", "count"), &Ed25519Wrapper::get_random_bytes);
    ClassDB::bind_method(D_METHOD("key_pair_from_seed", "seed"), &Ed25519Wrapper::key_pair_from_seed);
    ClassDB::bind_method(D_METHOD("key_pair_random"), &Ed25519Wrapper::key_pair_random);
    ClassDB::bind_method(D_METHOD("sign", "message", "private_key"), &Ed25519Wrapper::sign);
    ClassDB::bind_method(D_METHOD("verify", "signature", "message", "public_key"), &Ed25519Wrapper::verify);
}
