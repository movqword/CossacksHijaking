/* Cossacks hijaking exploit example (special for Habrahabr)
 *
 * project:	CossacksHijaking
 * file:    NetCore.cpp
 *
 * author:  Qword
 * date:    31.12.2016 9:14
 *
 * note:    
 */

#include "General.h"
#include "NetCore.h"
#include "NetPacket.h"
#include "Debug.h"
#include "Patcher.h"

#include <string>

//
//
//

unsigned char    NetCore::Buffer[kNetBufferSize];
unsigned int     NetCore::Offset;

//
// initialization
//

NetCore::NetCore() {
    Clear();
}

NetCore::~NetCore() {

}

//
// injection
//

void NetCore::Attach() {
    Patcher::At(kImportRecvCall)->Replace(OnReceive);
}

//
// data manimulation 
//

void NetCore::Clear() {
    std::memset(Buffer, 0, sizeof(Buffer));
    Offset = 0;
}

//
// ovveride windows calls
//

int WINAPI NetCore::OnReceive(SOCKET socket, char* buffer, int length, int flags) {
    // call to original

    int received_size = recv(socket, buffer, length, flags);

    // check for errors

    if (received_size <= 0) {
        return received_size;
    }

    Debug::Print("work!");

    // copy part to buffer

    std::memcpy(&Buffer[Offset], buffer, received_size);
    Offset += received_size;

    // start packet parsing

    NetPacketReader reader(Buffer);

    // return if packet not received fully

    if (Offset != reader.GetHeader()->Size + sizeof(NetPacketHeader)) {
        return received_size;
    }

    // handle by direction

    if (reader.GetHeader()->Direction == kNetPacketAccountLoginResult) {
        unsigned char result = reader.ReadByte();

        if (result != 0) {
            Debug::Print("login request aborted with error: %d", result);
            Clear();
            return received_size;
        }

        // requester info

        std::string requester_name(reader.ReadString());

        reader.ReadInt();
        reader.ReadInt();

        reader.ReadInt();
        reader.ReadShort();

        reader.ReadInt();
        reader.ReadShort();

        unsigned char requester_premium = reader.ReadByte();
        std::string requester_dlc(reader.ReadString());

        // user list

        while (true) {
            unsigned int user_index     = reader.ReadInt();
            unsigned char user_state    = reader.ReadByte();
            std::string user_name(reader.ReadString());
            unsigned char user_premium  = reader.ReadByte();
            std::string user_dlc(reader.ReadString());

            Debug::Print("[%d] user: %s", user_index, user_name.c_str());

            if (requester_name == user_name) { // last name = self, everytime
                break;
            }
        }

        reader.ReadInt();

        // lobby list

        while (true) {
            int room_index              = reader.ReadInt();

            if (room_index <= 0) {
                break;
            }

            int room_state              = reader.ReadInt();
            std::string room_title(reader.ReadString());
            std::string room_info(reader.ReadString());

            Debug::Print("[%d] room: %s", room_index, room_title.c_str());

            reader.ReadInt();
            reader.ReadShort();

            int room_user_count = reader.ReadInt();

            for (int i = 0; i < room_user_count; i++) {
                int room_user_index = reader.ReadInt();
            }
        }

        reader.ReadInt();
        reader.ReadShort();        
    }

    Clear();
    return received_size;
}
