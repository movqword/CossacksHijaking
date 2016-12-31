/* Cossacks hijaking exploit example (special for Habrahabr)
 *
 * project:	CossacksHijaking
 * file:    Patcher.h
 *
 * author:  Qword
 * date:    31.12.2016 9:33
 *
 * note:    
 */

#pragma once

#ifndef PATCHER_H
#define PATCHER_H

//
// 
//

#include <string>

//
//
//

enum eAsmOpsize {
    kAsmOpsizeNormal        = 5,    // 1 byte code + 4 bytes offset
    kAsmOpsizeLong          = 6,    // 2 bytes code + 4 bytes offset
};

enum eAsmOpcode {
    kAsmOpcodeNone          = 0xff,
    kAsmOpcodeNull          = 0x00,
    kAsmOpcodePush_Ax       = 0x50,
    kAsmOpcodePush_Cx       = 0x51,
    kAsmOpcodePush_Dx       = 0x52,
    kAsmOpcodePush_Bx       = 0x53,
    kAsmOpcodePush_Sp       = 0x54,
    kAsmOpcodePush_Bp       = 0x55,
    kAsmOpcodePush_Si       = 0x56,
    kAsmOpcodePush_Di       = 0x57,
    kAsmOpcodePush_Dword    = 0x68,
    kAsmOpcodePush_Byte     = 0x6a,
    kAsmOpcodeJo_Byte       = 0x70,
    kAsmOpcodeJno_Byte      = 0x71,
    kAsmOpcodeJb_Byte       = 0x72,
    kAsmOpcodeJnae_Byte     = 0x72,
    kAsmOpcodeJc_Byte       = 0x72,
    kAsmOpcodeJnb_Byte      = 0x73,
    kAsmOpcodeJae_Byte      = 0x73,
    kAsmOpcodeJnc_Byte      = 0x73,
    kAsmOpcodeJz_Byte       = 0x74,
    kAsmOpcodeJe_Byte       = 0x74,
    kAsmOpcodeJnz_Byte      = 0x75,
    kAsmOpcodeJne_Byte      = 0x75,
    kAsmOpcodeJbe_Byte      = 0x76,
    kAsmOpcodeJna_Byte      = 0x76,
    kAsmOpcodeJnbe_Byte     = 0x77,
    kAsmOpcodeJa_Byte       = 0x77,
    kAsmOpcodeJs_Byte       = 0x78,
    kAsmOpcodeJns_Byte      = 0x79,
    kAsmOpcodeJp_Byte       = 0x7a,
    kAsmOpcodeJpe_Byte      = 0x7a,
    kAsmOpcodeJnp_Byte      = 0x7b,
    kAsmOpcodeJpo_Byte      = 0x7b,
    kAsmOpcodeJl_Byte       = 0x7c,
    kAsmOpcodeJnge_Byte     = 0x7c,
    kAsmOpcodeJnl_Byte      = 0x7d,
    kAsmOpcodeJge_Byte      = 0x7d,
    kAsmOpcodeJle_Byte      = 0x7e,
    kAsmOpcodeJng_Byte      = 0x7e,
    kAsmOpcodeJnle_Byte     = 0x7f,
    kAsmOpcodeJg_Byte       = 0x7f,
    kAsmOpcodeNop           = 0x90,
    kAsmOpcodeCall_Dword    = 0xe8,
    kAsmOpcodeJmp_Dword     = 0xe9,
    kAsmOpcodeJmp_Byte      = 0xeb,
    kAsmOpcodeMovEax_Const  = 0xb8,
};

//
//
//

class Patcher {
private:
    //
    // initialization
    //

    Patcher();
    Patcher(const Patcher&);

public:
    //
    // access to instance
    //

    static Patcher* At(unsigned long offset);

public:
    //
    // common
    //

    bool GetBuffer(unsigned char* buffer, size_t size);
    bool SetBuffer(unsigned char* buffer, size_t size);

    template<class type> 
    type GetVariable(type default_result = 0);
    template<class type> 
    void SetVariable(type value);

    void Patch(eAsmOpcode value, unsigned long offset, size_t clear_size = 0);

public:
    //
    // range fill
    //

    void Fill(eAsmOpcode value, size_t size);
    void Clear(size_t size);

public:
    //
    // actions
    //

    template<class pointer>
    void Jump(pointer destination, size_t clear_size = 0) {
        Patch(kAsmOpcodeJmp_Dword, reinterpret_cast<unsigned long&>(destination), clear_size);
    }

    template<class pointer> 
    void Call(pointer destination, size_t clear_size = 0) {
        Patch(kAsmOpcodeCall_Dword, reinterpret_cast<unsigned long&>(destination), clear_size);
    }

    template<class pointer> 
    void Replace(pointer destination, bool is_relative = true) {
        if (is_relative) {
            Patch(kAsmOpcodeNone, reinterpret_cast<unsigned long&>(destination));
        }
        else {
            SetOffset(GetOffset() + 1);
            SetDword(reinterpret_cast<unsigned long&>(destination));
        }
    }

public:
    //
    // getters / setters for variables
    //

    unsigned char GetByte();
    void SetByte(unsigned char value);

    unsigned short GetWord();
    void SetWord(unsigned short value);

    unsigned long GetDword();
    void SetDword(unsigned long value);

    unsigned long long GetQword();
    void SetQword(unsigned long long value);

    float GetFloat();
    void SetFloat(float value);

    double GetDouble();
    void SetDouble(double value);

    std::string GetString(size_t size = 256);
    void SetString(std::string value, size_t clear_size = 0);

protected:
    //
    // helpers
    //

    unsigned long GetOffset();
    void SetOffset(unsigned long offset);

    template<class pointer> 
    unsigned long GetRelativeOffset(pointer destination) {
        return reinterpret_cast<unsigned long&>(destination) - GetOffset();
    }

private:
    //
    // data
    //

    unsigned long   _offset;
};


#endif // PATCHER_H
