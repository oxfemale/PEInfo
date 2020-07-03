#pragma once
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <Windows.h>
//
// Open up a file, memory map it, and call the appropriate dumping routine
//
bool DumpFile(LPCTSTR filename, bool abForceDetect);
