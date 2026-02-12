#include "Ed25519Wrapper.h"
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/dictionary.hpp>

using namespace godot;

Ed25519Wrapper::Ed25519Wrapper() {}
Ed25519Wrapper::~Ed25519Wrapper() {}

Dictionary Ed25519Wrapper::key_pair_from_seed(const PackedByteArray &seed) {
    Dictionary result;
    
    // Проверка размера seed (должен быть 32 байта для Ed25519)
    if (seed.size() != 32) {
        ERR_PRINT("Seed must be exactly 32 bytes.");
        return result;
    }

    uint8_t secret_key[64];
    uint8_t public_key[32];
    uint8_t seed_copy[32]; // Monocypher очищает буфер seed, поэтому копируем

    // Копируем данные из Godot массива в C-буфер
    memcpy(seed_copy, seed.ptr(), 32);

    // Вызов Monocypher
    crypto_eddsa_key_pair(secret_key, public_key, seed_copy);

    // Конвертируем обратно в PackedByteArray для Godot
    PackedByteArray pba_private;
    pba_private.resize(64);
    memcpy(pba_private.ptrw(), secret_key, 64);

    PackedByteArray pba_public;
    pba_public.resize(32);
    memcpy(pba_public.ptrw(), public_key, 32);

    // Очистка чувствительных данных в памяти C++ (опционально, но хорошая практика)
    crypto_wipe(secret_key, 64);
    crypto_wipe(seed_copy, 32);

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

    signature.resize(64);
    
    // Вызов Monocypher
    // .ptr() дает доступ к чтению const uint8_t*
    // .ptrw() дает доступ к записи uint8_t*
    crypto_eddsa_sign(
        signature.ptrw(), 
        private_key.ptr(), 
        message.ptr(), 
        message.size()
    );

    return signature;
}

bool Ed25519Wrapper::verify(const PackedByteArray &signature, const PackedByteArray &message, const PackedByteArray &public_key) {
    if (signature.size() != 64 || public_key.size() != 32) {
        return false;
    }

    // crypto_eddsa_check возвращает 0 при успехе, -1 при ошибке
    int result = crypto_eddsa_check(
        signature.ptr(),
        public_key.ptr(),
        message.ptr(),
        message.size()
    );

    return (result == 0);
}

void Ed25519Wrapper::_bind_methods() {
    ClassDB::bind_method(D_METHOD("key_pair_from_seed", "seed"), &Ed25519Wrapper::key_pair_from_seed);
    ClassDB::bind_method(D_METHOD("sign", "message", "private_key"), &Ed25519Wrapper::sign);
    ClassDB::bind_method(D_METHOD("verify", "signature", "message", "public_key"), &Ed25519Wrapper::verify);
}