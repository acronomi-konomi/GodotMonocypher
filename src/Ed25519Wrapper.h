#ifndef ED25519_WRAPPER_H
#define ED25519_WRAPPER_H

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>

// Подключаем библиотеку
#include "monocypher.h"

namespace godot {

class Ed25519Wrapper : public RefCounted {
    GDCLASS(Ed25519Wrapper, RefCounted)

protected:
    static void _bind_methods();

public:
    Ed25519Wrapper();
    ~Ed25519Wrapper();

    // Генерация пары ключей из seed (32 байта)
    // Возвращает словарь { "private": PackedByteArray, "public": PackedByteArray }
    Dictionary key_pair_from_seed(const PackedByteArray &seed);

    // Подпись сообщения
    // Возвращает подпись (64 байта)
    PackedByteArray sign(const PackedByteArray &message, const PackedByteArray &private_key);

    // Проверка подписи
    bool verify(const PackedByteArray &signature, const PackedByteArray &message, const PackedByteArray &public_key);
};

} // namespace godot

#endif