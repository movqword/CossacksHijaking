/* Cossacks hijaking exploit example (special for Habrahabr)
 *
 * project:	CossacksHijaking
 * file:    NetPacket.h
 *
 * author:  Qword
 * date:    31.12.2016 9:41
 *
 * note:    
 */

#ifndef NET_PACKET_H
#define NET_PACKET_H

#pragma once

//
//
//

#include "Config.h"

#include <string>

//
//
//

enum {
    kNetPacketAccountFindRequest = 0xA8,
    kNetPacketAccountFindResult = 0xA9,
    kNetPacketAccountRestoreRequest = 0xB9,
    kNetPacketAccountCreateRequest = 0x98,
    kNetPacketAccountCreateResult = 0x99,
    kNetPacketAccountLoginRequest = 0x9A,
    kNetPacketAccountLoginResult = 0x9B,

    kNetPacketChatRequest = 0x96,
    kNetPacketChatResult = 0x97,

    kNetPacketRoomCreateRequest = 0x9C,
    kNetPacketRoomCreateResult = 0x9D,
    kNetPacketRoomEnterRequest = 0x9E,
    kNetPacketRoomEnterResult = 0x9F,
    kNetPacketRoomEnterNotify = 0x65,
    kNetPacketRoomLeaveRequest = 0xA0,
    kNetPacketRoomLeaveResult = 0xA1,
    kNetPacketRoomUpdateNotify = 0xA5,
    kNetPacketRoomKickRequest = 0xB5,
    kNetPacketRoomKickResult = 0xB6,

    kNetPacketLobbyEnterNotify = 0xA6,
    kNetPacketLobbyLeaveNotify = 0xA7,
};

//
//
//

#pragma pack(push, 1)
struct NetPacketHeader {
    NetPacketHeader() {
        Size        = 0;
        Direction   = 0;
        Mode        = 1;
        SessionId0  = 0;
        SessionId1  = 0;
    }

    NetPacketHeader(unsigned int size, unsigned char direction) {
        Size        = size;
        Direction   = direction;
        Mode        = 1;
        SessionId0  = 0;
        SessionId1  = 0;
    }

    NetPacketHeader(unsigned int size, unsigned char direction, unsigned char mode) {
        Size        = size;
        Direction   = direction;
        Mode        = mode;
        SessionId0  = 0;
        SessionId1  = 0;
    }

    NetPacketHeader(unsigned int size, unsigned char direction, unsigned char mode, int id0, int id1) {
        Size        = size;
        Direction   = direction;
        Mode        = mode;
        SessionId0  = id0;
        SessionId1  = id1;
    }

public:
    //
    // data
    //

    unsigned int    Size;
    unsigned char   Direction;
    unsigned char   Mode;
    unsigned int    SessionId0;
    unsigned int    SessionId1;
};
#pragma pack(pop)

//
//
//

class NetPacketReader {
public:
    //
    //
    //

    NetPacketReader(unsigned char* buffer) {
        _buffer = buffer;
        _offset = sizeof(NetPacketHeader);
    }

    ~NetPacketReader() {

    }

    //
    //
    //

    unsigned char* ReadBlock(size_t size) {
        unsigned char* result = new unsigned char[size];
        std::memcpy(result, &_buffer[_offset], size);
        return result;
    }

    unsigned char ReadByte() {
        unsigned char result = _buffer[_offset];

        _offset += sizeof(unsigned char);
        return result;
    }

    short ReadShort() {
        short result = reinterpret_cast<short&>(_buffer[_offset]);

        _offset += sizeof(short);
        return result;
    }

    unsigned short ReadUShort() {
        return static_cast<unsigned>(ReadShort());
    }

    int ReadInt() {
        int result = reinterpret_cast<int&>(_buffer[_offset]);

        _offset += sizeof(int);
        return result;
    }

    unsigned int ReadUInt() {
        return static_cast<unsigned>(ReadInt());
    }

    char* ReadString(size_t size = 0) {
        if (size == 0) {
            size = ReadByte();
        }

        static char result[5000];
        std::memset(result, 0, sizeof(result));
        std::memcpy(result, &_buffer[_offset], size);

        _offset += size;
        return result;
    }

public:
    //
    //
    //

    void SetBuffer(unsigned char* value) {
        _buffer = value;
    }

    NetPacketHeader* GetHeader() {
        return reinterpret_cast<NetPacketHeader*>(_buffer);
    }

	size_t GetOffset() {
		return _offset;
	}

private:
    //
    //
    //

    unsigned char*  _buffer = nullptr;
    size_t          _offset = 0;
};

//
//
//

class NetPacketWriter {
public:
    //
    //
    //

    NetPacketWriter() {
        _offset = sizeof(NetPacketHeader);
    }

    ~NetPacketWriter() {

    }

    //
    //
    //

    void WriteBlock(unsigned char* value, size_t size) {
        std::memcpy(&_buffer[_offset], value, size);
        _offset += size;
    }

    void WriteByte(unsigned char value) {
        _buffer[_offset] = value;
        _offset += sizeof(unsigned char);
    }

    void WriteShort(short value) {
        std::memcpy(&_buffer[_offset], &value, sizeof(short));
        _offset += sizeof(short);
    }

    void WriteUShort(unsigned short value) {
        WriteShort(static_cast<signed>(value));
    }

    void WriteInt(int value) {
        std::memcpy(&_buffer[_offset], &value, sizeof(int));
        _offset += sizeof(int);
    }

    void WriteUInt(unsigned int value) {
        WriteInt(static_cast<signed>(value));
    }

    void WriteString(const char* value, size_t size = 0) {
        if (size == 0) {
            size = std::strlen(value);
            WriteByte(size);
        }

        std::memcpy(&_buffer[_offset], value, size);
        _offset += size;
    }

    void WriteString(const std::string value) {
        WriteByte(value.size());

        std::memcpy(&_buffer[_offset], value.c_str(), value.size());
        _offset += value.size();
    }

public:
    //
    //
    //

    unsigned char* GetBuffer() {
        return _buffer;
    }

    size_t GetBufferSize() {
        return _offset;
    }

    size_t GetDataSize() {
        return _offset - sizeof(NetPacketHeader);
    }

    void SetHeader(NetPacketHeader& header) {
        std::memcpy(_buffer, &header, sizeof(NetPacketHeader));
    }

private:
    //
    //
    //

    unsigned char   _buffer[kNetBufferSize];
    size_t          _offset = 0;
};

#endif // NET_PACKET_H
