#ifndef ED25519_WRAPPER_H
#define ED25519_WRAPPER_H

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <godot_cpp/variant/dictionary.hpp>

namespace godot {

class Ed25519Wrapper : public RefCounted {
    GDCLASS(Ed25519Wrapper, RefCounted)

protected:
    static void _bind_methods();

public:
    Ed25519Wrapper();
    ~Ed25519Wrapper();

    // Генерация случайных байтов (через OS Godot)
    PackedByteArray get_random_bytes(int count);

    // Создать пару ключей из 32-байтного Seed
    // Возвращает: { "private": [64 bytes], "public": [32 bytes] }
    Dictionary key_pair_from_seed(const PackedByteArray &seed);

    // Создать случайную пару ключей
    Dictionary key_pair_random();

    // Подписать сообщение
    // Возвращает: 64 байта подписи
    PackedByteArray sign(const PackedByteArray &message, const PackedByteArray &private_key);

    // Проверить подпись
    // Возвращает: true/false
    bool verify(const PackedByteArray &signature, const PackedByteArray &message, const PackedByteArray &public_key);
};

} // namespace godot

#endif