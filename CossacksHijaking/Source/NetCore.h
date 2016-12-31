/* Cossacks hijaking exploit example (special for Habrahabr)
 *
 * project:	CossacksHijaking
 * file:    NetCore.h
 *
 * author:  Qword
 * date:    31.12.2016 9:14
 *
 * note:    
 */

#ifndef NET_CORE_H
#define NET_CORE_H

#pragma once

//
// 
//

#include "Config.h"

#include <winsock.h>

//
// description
//

class NetCore {
public:
    //
    // initialization
    //

    NetCore();
    ~NetCore();

public:
    //
    // injection
    //

    static void Attach();

protected:
    //
    // data manimulation 
    //

    static void Clear();

public:
    //
    // ovveride windows calls
    //

    static int WINAPI OnReceive(SOCKET socket, char* buffer, int length, int flags);

public:
    //
    // data
    //

    static unsigned char    Buffer[kNetBufferSize];
    static unsigned int     Offset;
};

#endif // NET_CORE_H
