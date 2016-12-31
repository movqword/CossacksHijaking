/* Cossacks hijaking exploit example (special for Habrahabr)
 *
 * project:	CossacksHijaking
 * file:    General.cpp
 *
 * author:  Qword
 * date:    31.12.2016 9:06
 *
 * note:    
 */

#include "General.h"
#include "NetCore.h"

//
// forward declaration
//

void OnAttach();

//
// entry point
//

int WINAPI DllMain(HMODULE module, unsigned long reason_for_call, void* reserved) {
    switch (reason_for_call) {
    case DLL_PROCESS_ATTACH:
        OnAttach();
        break;
    }

    return 1;
}

//
// attach event
//

void OnAttach() {
    // loading original dll
    
    LoadLibraryA("vorbisfile_.dll");

    // initialization of hooks

    NetCore::Attach();
}
