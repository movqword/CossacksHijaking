/* Cossacks hijaking exploit example (special for Habrahabr)
 *
 * project:	CossacksHijaking
 * file:    Config.h
 *
 * author:  Qword
 * date:    31.12.2016 9:16
 *
 * note:    
 */

#ifndef CONFIG_H
#define CONFIG_H

#pragma once

//
//
//

enum {
    kNetBufferSize  = 50000,
};

//
//
//

enum {
    kImportRecvCall = 0x5B1B9B, // ok for 31.12.2016
};

#endif // CONFIG_H
