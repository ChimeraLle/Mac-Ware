//
// Created by Yoru on 5/8/2024.
//
#include "LuaState.hpp"
#include <iostream>

#include "../Luau/include/lualib.h"
#include "../Compiler/include/Compiler.h"
#include "../Compiler/include/BytecodeBuilder.h"
#include "../Compiler/include/luacode.h"
#include "../Instance/RobloxInstance.hpp"
#include "../zstd/include/xxhash.h"
#include "../zstd/include/zstd.h"
#include <WinInet.h>
#include <fstream>
#include "externs.h"

class bytecode_encoder_t : public Luau::BytecodeEncoder
{
public://bytecode encoder class that gets the opcode
    std::uint8_t encodeOp(const std::uint8_t opcode) override
    {
        return opcode * 227;
    }
};

LuaState* LuaState::g_Singleton = nullptr;

const auto pDriver{ Driver::get_singleton() };

LuaState* LuaState::get_singleton() noexcept {
	if (g_Singleton == nullptr)
		g_Singleton = new LuaState();
	return g_Singleton;
}

void LuaState::initialize(std::uint64_t lua_state) {
    this->LS = lua_state;
}

// credits: speedsterkawaii
// for: compress_source

std::string compress_source(const std::string& data)
{
    std::string output = "RSB1";
    std::string input = "HEXDEV";
    const std::size_t dataSize = data.size();
    const std::size_t maxSize = ZSTD_compressBound(dataSize);
    std::vector<char> compressed(maxSize);
    const std::size_t compSize = ZSTD_compress(&compressed[0], maxSize, data.c_str(), dataSize, ZSTD_maxCLevel());
    output.append(reinterpret_cast<const char*>(&dataSize), sizeof(dataSize));
    output.append(&compressed[0], compSize);
    const std::uint32_t firstHash = XXH32(&output[0], output.size(), 42U);
    std::uint8_t hashedBytes[4];
    std::memcpy(hashedBytes, &firstHash, sizeof(firstHash));
    input.append("\n\n" + output);
    for (std::size_t i = 0; i < output.size(); ++i)
    {
        output[i] ^= hashedBytes[i % 4] + i * 41U;
    }
    return output;
}

void LuaState::Run(std::string source, uintptr_t base) {
    const uintptr_t ctx_defer = base + 0x1076190;
    const uintptr_t luau_load = base + 0xc82540;
    
    typedef int(__cdecl* CTXDeferType)(IN uintptr_t state);
    const CTXDeferType RCtxDefer = reinterpret_cast<CTXDeferType>(ctx_defer);

    typedef int(__cdecl* LuaULoadType)(IN uintptr_t state, IN const char *chunkname, IN const char *data, IN int env);
    const LuaULoadType RLuaU_Load = reinterpret_cast<LuaULoadType>(luau_load);

    bytecode_encoder_t encoder;
    std::string bytecode = Luau::compile(source, {}, {}, &encoder);
    std::string compressed_btc = compress_source(bytecode);

    //PoolPartyCall(RLuaU_Load(this->LS, "=ThanksAzox", compressed_btc.c_str(), NULL));
    //PoolPartyCall(RCtxDefer(this->LS));

    uintptr_t* StackTop = reinterpret_cast<uintptr_t*>(this->LS + 0x18);
    *StackTop -= 16;
}

void LuaState::set_identity(int identityy) {
    this->identity = identityy;
    auto LS_UserData = pDriver->read<std::uint64_t>(this->LS + 0x78);

    auto old_identity = pDriver->read<unsigned long>(LS_UserData + 0x30);
    auto old_capabilities = pDriver->read<unsigned long>(LS_UserData + 0x48);
    std::cout << std::hex << old_identity << std::endl;
    std::cout << std::hex << old_capabilities << std::endl;

    pDriver->write<unsigned long>(LS_UserData + 0x30, this->identity); // identity
    pDriver->write<unsigned long>(LS_UserData + 0x48, 0x3F | 0x3FFFF00); // capabilities, hardcoded to identities 7/8
}

void CallRemoteFunction(HANDLE hProcess, uintptr_t remoteFunc, uintptr_t arg1, const char* arg2 = nullptr, const char* arg3 = nullptr, int arg4 = 0) {
    SIZE_T argSize = sizeof(uintptr_t) + (arg2 ? strlen(arg2) + 1 : 0) + (arg3 ? strlen(arg3) + 1 : 0) + sizeof(int);
    void* remoteArgs = VirtualAllocEx(hProcess, NULL, argSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteArgs) {
        std::cerr << "Failed to allocate memory for arguments in the remote process.\n";
        return;
    }

    uintptr_t args[4];
    args[0] = arg1;
    if (arg2) {
        void* remoteArg2 = (void*)((uintptr_t)remoteArgs + sizeof(uintptr_t));
        WriteProcessMemory(hProcess, remoteArg2, arg2, strlen(arg2) + 1, NULL);
        args[1] = (uintptr_t)remoteArg2;
    }
    if (arg3) {
        void* remoteArg3 = (void*)((uintptr_t)remoteArgs + sizeof(uintptr_t) + (arg2 ? strlen(arg2) + 1 : 0));
        WriteProcessMemory(hProcess, remoteArg3, arg3, strlen(arg3) + 1, NULL);
        args[2] = (uintptr_t)remoteArg3;
    }
    args[3] = arg4;

    WriteProcessMemory(hProcess, remoteArgs, args, sizeof(args), NULL);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteFunc, remoteArgs, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread.\n";
        VirtualFreeEx(hProcess, remoteArgs, 0, MEM_RELEASE);
        return;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteArgs, 0, MEM_RELEASE);
}

