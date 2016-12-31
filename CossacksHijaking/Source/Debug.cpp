/* Cossacks hijaking exploit example (special for Habrahabr)
 *
 * project:	CossacksHijaking
 * file:    Debug.cpp
 *
 * author:  Qword
 * date:    31.12.2016 9:33
 *
 * note:    
 */

#include "General.h"
#include "Debug.h"

#include <cstdarg>      // work with variable arguments
#include <stdio.h>      // vsprintf_s / _vscprintf

//
//
//

void Debug::Print(const char* text, ...) {
    va_list arguments_list;
    va_start(arguments_list, text);

    size_t string_buffer_lenght = _vscprintf(text, arguments_list) + 1;
    char* string_buffer         = new char[string_buffer_lenght * sizeof(char)];

    vsprintf_s(string_buffer, string_buffer_lenght, text, arguments_list);

    va_end(arguments_list);

    string_buffer[string_buffer_lenght - 1] = '\0';
    OutputDebugString(string_buffer);

    delete[] string_buffer;
}
