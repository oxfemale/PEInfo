// detect.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//
#include "stdafx.h"
#define _UNICODE 1
#define UNICODE 1
//#pragma comment(lib, "ntdll.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#include <imagehlp.h>
#include <string.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <iostream>
#include <Winternl.h>
#include <Windows.h>
#include <imagehlp.h>
#include <time.h>
#include <string.h>
#include <delayimp.h>
#include "COFFSymbolTable.h"
#include "COMMON.h"
#include "cv_dbg.h"
#include "cvexefmt.h"
#include "cvinfo.h"
#include "CVInfoNew.h"
#include "cvsymbols.h"
#include "extrnvar.h"
#include "dbgdump.h"
#include "peinfo.h"
#include "exedump.h"
#include "extrnvar.h"
#include "libdump.h"
#include "objdump.h"
#include "os2.h"
#include "resdump.h"
#include "romimage.h"
#include "symboltablesupport.h"
#include "pedump.h"

//#pragma comment(lib, "Dbghelp.lib")

bool gbUseUndecorate;
bool gbDecimalIds;

typedef DWORD(WINAPI* UnDecorateSymbolName_t)(const char* DecoratedName, char* UnDecoratedName, DWORD UndecoratedLength, DWORD Flags);
UnDecorateSymbolName_t UnDecorate_Dbghelp;

int main(int argc, char* argv[])
{
    _tprintf(_T("Recoded FAR ImpEx plugin to .exe tool by @bytecodevm //\r\nGOA\x20music\x20in\x20heart\t[%00X]\r\n"),7331);
    gbUseUndecorate = 1;
    gbDecimalIds = 1;
    HMODULE ghDbghelp = LoadLibrary(_T("Dbghelp.dll"));
    if (ghDbghelp)
    {
        UnDecorate_Dbghelp = 0;
        UnDecorate_Dbghelp = (UnDecorateSymbolName_t)GetProcAddress(ghDbghelp, "UnDecorateSymbolName");
        if (!UnDecorate_Dbghelp)
        {
            printf("Error load UnDecorateSymbolName() from Dbghelp.dll\r\n");
            return 0;
        }
    }
    else {
        printf("Error: Dbghelp.dll not found.\r\n ");
        return 0;
    }
    
    if (argc > 1)
    {
        DumpFile(argv[1], true);
    }
    else
    {
        _tprintf("Error: need filename or file path argument.\r\n"
            "\r\nExample: "
            "\r\nRUNNING "
            "\r\n%s %s"
            "\r\nwait 3 sec and start demo\r\n", argv[0], argv[0]);
        for (int counter = 0; counter < 10; counter++)
        {
            Sleep(300);
            printf(".");
        }

        printf("\r\n");
        DumpFile(argv[0], true);
    }

    return 0;
}

