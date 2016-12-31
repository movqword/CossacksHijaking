/* Cossacks hijaking exploit example (special for Habrahabr)
 *
 * project:	CossacksHijaking
 * file:    Patcher.cpp
 *
 * author:  Qword
 * date:    31.12.2016 9:33
 *
 * note:    
 */

#include "General.h"
#include "Patcher.h"
#include "Debug.h"

//
// initialization
//

Patcher::Patcher() {

}

Patcher::Patcher(const Patcher&) {

}

//
// access to instance
//

Patcher* Patcher::At(unsigned long offset) {
    static Patcher instance;

    instance.SetOffset(offset);
    return &instance;
}

//
// common
//

bool Patcher::GetBuffer(unsigned char* buffer, size_t size) {
    unsigned long current_flag = 0, new_flag = 0;

    if (size <= 0) {
        return false;
    }

    // change protection
    if (VirtualProtect(reinterpret_cast<void*>(GetOffset()), size, PAGE_EXECUTE_READWRITE, &current_flag) == 0) {
        return false;
    }

    memcpy(buffer, reinterpret_cast<void*>(GetOffset()), size);

    // restore protection
    if (VirtualProtect(reinterpret_cast<void*>(GetOffset()), size, current_flag, &new_flag) == 0) {
        return false;
    }

    return true;
}

bool Patcher::SetBuffer(unsigned char* buffer, size_t size) {
    unsigned long current_flag = 0, new_flag = 0;

    if (size <= 0) {
        return false;
    }

    // change protection
    if (VirtualProtect(reinterpret_cast<void*>(GetOffset()), size, PAGE_EXECUTE_READWRITE, &current_flag) == 0) { 
        return false;
    }

    memcpy(reinterpret_cast<void*>(GetOffset()), buffer, size);

    // restore protection
    if (VirtualProtect(reinterpret_cast<void*>(GetOffset()), size, current_flag, &new_flag) == 0) {
        return false;
    }

    return true;
}

template<class type> 
type Patcher::GetVariable(type default_result) {
    type result = default_result;

    if (!GetBuffer(reinterpret_cast<unsigned char*>(&result), sizeof(type))) {
        Debug::Print("(%s) failed to read data at %x offset", __FUNCTION__, GetOffset());
    }

    return result;
}

template<class type> 
void Patcher::SetVariable(type value) {
    if (!SetBuffer(reinterpret_cast<unsigned char*>(&value), sizeof(type))) {
        Debug::Print("(%s) failed to write data at %x offset", __FUNCTION__, GetOffset());
    }
}

void Patcher::Patch(eAsmOpcode value, unsigned long destination, size_t clear_size) {
    if (clear_size > 0) { 
        Clear(clear_size); 
    }

    unsigned char buffer[kAsmOpsizeNormal] = { 0 };
    unsigned long offset = GetRelativeOffset(destination) - sizeof(buffer);

    if (value == kAsmOpcodeNone) {
        SetOffset(GetOffset() + 1);
        SetDword(GetRelativeOffset(destination) - sizeof(offset));
        return;
    }

    buffer[0] = (BYTE)value;
    memcpy(reinterpret_cast<void*>(&buffer[1]), reinterpret_cast<void*>(&offset), sizeof(offset));

    SetBuffer(buffer, sizeof(buffer));
}

//
// range fill
//

void Patcher::Fill(eAsmOpcode value, size_t size) {
    if (size <= 0) {
        return;
    }

    unsigned char* buffer = new unsigned char[size];
    memset(reinterpret_cast<void*>(buffer), value, size);

    SetBuffer(buffer, size);
    delete[] buffer;
}

void Patcher::Clear(size_t size) {
    Fill(kAsmOpcodeNop, size);
}

//
// getters / setters for variables
//

unsigned char Patcher::GetByte() {
    return GetVariable<unsigned char>();
}

void Patcher::SetByte(unsigned char value) {
    SetVariable<unsigned char>(value);
}

unsigned short Patcher::GetWord() {
    return GetVariable<unsigned short>();
}

void Patcher::SetWord(unsigned short value) {
    SetVariable<unsigned short>(value);
}

unsigned long Patcher::GetDword() {
    return GetVariable<unsigned long>();
}

void Patcher::SetDword(unsigned long value) {
    SetVariable<unsigned long>(value);
}

unsigned long long Patcher::GetQword() {
    return GetVariable<unsigned long long>();
}

void Patcher::SetQword(unsigned long long value) {
    SetVariable<unsigned long long>(value);
}

float Patcher::GetFloat() {
    return GetVariable<float>();
}

void Patcher::SetFloat(float value) {
    SetVariable<float>(value);
}

double Patcher::GetDouble() {
    return GetVariable<double>();
}

void Patcher::SetDouble(double value) {
    SetVariable<double>(value);
}

std::string Patcher::GetString(size_t size) {
    char* buffer = new char[size];    
    GetBuffer(reinterpret_cast<unsigned char*>(buffer), size);
    return std::string(buffer);
}

void Patcher::SetString(std::string value, size_t clear_size) {
    if (clear_size > 0) {
        Fill(kAsmOpcodeNull, clear_size);
    }

    SetBuffer(reinterpret_cast<unsigned char*>(const_cast<char*>(value.c_str())), value.size());
}

//
// helpers
//

unsigned long Patcher::GetOffset() {
    return _offset;
}

void Patcher::SetOffset(unsigned long offset) {
    _offset = offset;
}
