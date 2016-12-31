/* Cossacks hijaking exploit example (special for Habrahabr)
 *
 * project:	CossacksHijaking
 * file:    Debug.h
 *
 * author:  Qword
 * date:    31.12.2016 9:33
 *
 * note:    
 */

#pragma once

#ifndef DEBUG_H
#define DEBUG_H

//
// debug helper implementation (pure static)
//

class Debug {
public:
    static void Print(const char* text, ...);
};

#endif // DEBUG_H
