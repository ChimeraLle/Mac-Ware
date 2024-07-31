#pragma once

#include <cstdint>
#include <fstream>
#include "../../driver/Driver.h"

enum Identity { One_Four = 3, Two = 0, Five = 1, Three_Six = 0xB, Eight_Seven = 0x3F, Nine = 0xC };

class LuaState {
    static LuaState* g_Singleton;

public:
    static LuaState* get_singleton() noexcept;

    void initialize(std::uint64_t lua_state);
    void Run(std::string source, uintptr_t base);
    void set_identity(int identity);

    std::uint64_t LS;
    unsigned long identity;
    unsigned long capabilities;
};
