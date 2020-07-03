
#include "stdafx.h"
#include <stdio.h>
#include "COMMON.H"

// This is 16bit PE browser

void GetResourceTypeName(DWORD type, PSTR buffer, UINT cBytes);

// Get an ASCII string representing a resource type
void GetOS2ResourceTypeName(DWORD type, PSTR buffer, UINT cBytes)
{
	if ((type & 0x8000) == 0x8000) {
		GetResourceTypeName(type & 0x7FFF, buffer, cBytes-10);
		strcat(buffer, " [16bit]");
	} else {
		GetResourceTypeName(type, buffer, cBytes);
	}
}

typedef struct tag_OS2RC_TNAMEINFO {
	USHORT rnOffset;
	USHORT rnLength;
	UINT   rnID;
	USHORT rnHandle;
	USHORT rnUsage;
} OS2RC_TNAMEINFO, *POS2RC_TNAMEINFO;

typedef struct tag_OS2RC_TYPEINFO {
	USHORT rtTypeID;
	USHORT rtResourceCount;
	UINT   rtReserved;
	OS2RC_TNAMEINFO rtNameInfo[1];
} OS2RC_TYPEINFO, *POS2RC_TYPEINFO;

void* CreateResource(  
						   DWORD rootType, LPVOID ptrRes, DWORD resSize,
						   LPCSTR asID, LPCSTR langID, DWORD stringIdBase, DWORD anLangId);


void DumpNEResourceTable(  PIMAGE_DOS_HEADER dosHeader, LPBYTE pResourceTable)
{
	PBYTE pImageBase = (PBYTE)dosHeader;


	// минимальный размер
	size_t nReqSize = sizeof(OS2RC_TYPEINFO)+12;
	if (!ValidateMemory(pResourceTable, nReqSize)) {
		printf( "!!! Can't read memory at offset:  0x%08X\n",
			(DWORD)(pResourceTable - pImageBase));
		return;
	}

	//
	USHORT rscAlignShift = *(USHORT*)pResourceTable;
	OS2RC_TYPEINFO* pTypeInfo = (OS2RC_TYPEINFO*)(pResourceTable+2);
	char szTypeName[128], szResName[256];
	UINT nResLength = 0, nResOffset = 0;
	LPBYTE pNames;

	// —начала нужно найти начало имен
	pTypeInfo = (OS2RC_TYPEINFO*)(pResourceTable+2);
	while (pTypeInfo->rtTypeID) {
		OS2RC_TNAMEINFO* pResName = pTypeInfo->rtNameInfo;

		// Next resource type
		pTypeInfo = (OS2RC_TYPEINFO*)(pResName+pTypeInfo->rtResourceCount);
		if (!ValidateMemory(pTypeInfo, 2)) {
			printf( "!!! Can't read memory at offset:  0x%08X\n",
				(DWORD)(((LPBYTE)pTypeInfo) - pImageBase));
			return;
		}
	}
	pNames = ((LPBYTE)pTypeInfo)+2;

	// “еперь, собственно ресурсы
	pTypeInfo = (OS2RC_TYPEINFO*)(pResourceTable+2);
	while (pTypeInfo->rtTypeID) {
		szTypeName[0] = 0;
		GetOS2ResourceTypeName(pTypeInfo->rtTypeID, szTypeName, sizeof(szTypeName));

		printf("  <%s>:\n", szTypeName);

		printf( "    Resource count:   %i\n", pTypeInfo->rtResourceCount);

		OS2RC_TNAMEINFO* pResName = pTypeInfo->rtNameInfo;
		for (USHORT i = pTypeInfo->rtResourceCount; i--; pResName++) {
			nResLength = pResName->rnLength * (1 << rscAlignShift);
			nResOffset = pResName->rnOffset * (1 << rscAlignShift);

			szResName[0] = 0;
			if (pNames) {
				if (!ValidateMemory(pNames, 1)) {
					printf( "!!! Can't read memory at offset:  0x%08X\n",
						(DWORD)(pNames - pImageBase));
					pNames = NULL;
				} else if (!ValidateMemory(pNames, 1+(*pNames))) {
					printf( "!!! Can't read memory at offset:  0x%08X\n",
						(DWORD)(pNames - pImageBase));
					pNames = NULL;
				} else if (*pNames) {
					memmove(szResName, pNames+1, *pNames);
					szResName[*pNames] = 0;
					pNames += (*pNames)+1;
				} else {
					pNames++;
				}
			}
			if (szResName[0]) {
				sprintf(szResName+strlen(szResName), ".0x%08X", pResName->rnID);
			} else {
				sprintf(szResName, "ResID=0x%08X", pResName->rnID);
			}


			printf("    <%s>\n", szResName);
			printf("      Resource Name:    %s\n", szResName);
			printf("      Resource ID:      0x%08X\n", pResName->rnID);
			printf("      Resource length:  %u bytes\n", nResLength);
			printf("      Resource offset:  0x%08X\n", nResOffset);
			printf("      Handle(reserved): 0x%04X\n", (DWORD)pResName->rnHandle);
			printf("      Usage(reserved):  0x%04X\n", (DWORD)pResName->rnUsage);
			//if (nResLength && nResOffset) {
			//	pRes->SetData(pImageBase+nResOffset, nResLength);
			//}
		}


		// Next resource type
		pTypeInfo = (OS2RC_TYPEINFO*)pResName;
	}
}

bool DumpExeFileNE(   PIMAGE_DOS_HEADER dosHeader, PIMAGE_OS2_HEADER pOS2Header )
{
	PBYTE pImageBase = (PBYTE)dosHeader;

	DumpHeader(  dosHeader);



	if (pOS2Header->ne_magic != IMAGE_OS2_SIGNATURE) {
		printf( "  IMAGE_OS2_SIGNATURE_LE signature not supported\n");
		return true;
	}

	printf( "  Signature:                          IMAGE_OS2_SIGNATURE\n");  

	printf( "  Version number:                     %u\n", (UINT)pOS2Header->ne_ver);
	printf( "  Revision number:                    %u\n", (UINT)pOS2Header->ne_rev);
	printf( "  Offset of Entry Table:              %u\n", (UINT)pOS2Header->ne_enttab);
	printf( "  Number of bytes in Entry Table:     %u\n", (UINT)pOS2Header->ne_cbenttab);
	printf( "  Checksum of whole file:             0x%08X\n", (UINT)pOS2Header->ne_crc);
	printf( "  Flag word:                          0x%04X\n", (UINT)pOS2Header->ne_flags);
	printf( "  Automatic data segment number:      %u\n", (UINT)pOS2Header->ne_autodata);
	printf( "  Initial heap allocation:            %u\n", (UINT)pOS2Header->ne_heap);
	printf( "  Initial stack allocation:           %u\n", (UINT)pOS2Header->ne_stack);
	printf( "  Initial CS:IP setting:              0x%08X\n", (UINT)pOS2Header->ne_csip);
	printf( "  Initial SS:SP setting:              0x%08X\n", (UINT)pOS2Header->ne_sssp);
	printf( "  Count of file segments:             %u\n", (UINT)pOS2Header->ne_cseg);
	printf( "  Entries in Module Reference Table:  %u\n", (UINT)pOS2Header->ne_cmod);
	printf( "  Size of non-resident name table:    %u\n", (UINT)pOS2Header->ne_cbnrestab);
	printf( "  Offset of Segment Table:            %u\n", (UINT)pOS2Header->ne_segtab);
	printf( "  Offset of Resource Table:           %u\n", (UINT)pOS2Header->ne_rsrctab);
	printf( "  Offset of resident name table:      %u\n", (UINT)pOS2Header->ne_restab);
	printf( "  Offset of Module Reference Table:   %u\n", (UINT)pOS2Header->ne_modtab);
	printf( "  Offset of Imported Names Table:     %u\n", (UINT)pOS2Header->ne_imptab);
	printf( "  Offset of Non-resident Names Table: %u\n", (UINT)pOS2Header->ne_nrestab);
	printf( "  Count of movable entries:           %u\n", (UINT)pOS2Header->ne_cmovent);
	printf( "  Segment alignment shift count:      %u\n", (UINT)pOS2Header->ne_align);
	printf( "  Count of resource segments:         %u\n", (UINT)pOS2Header->ne_cres);
	printf( "  Target Operating system:            %u\n", (UINT)pOS2Header->ne_exetyp);
	printf( "  Other .EXE flags:                   0x%02X\n", (UINT)pOS2Header->ne_flagsothers);
	printf( "  offset to return thunks:            %u\n", (UINT)pOS2Header->ne_pretthunks);
	printf( "  offset to segment ref. bytes:       %u\n", (UINT)pOS2Header->ne_psegrefbytes);
	printf( "  Minimum code swap area size:        %u\n", (UINT)pOS2Header->ne_swaparea);
	printf( "  Expected Windows version number:    %u.%u\n", (UINT)HIBYTE(pOS2Header->ne_expver), (UINT)LOBYTE(pOS2Header->ne_expver));

	printf( "\n");

	if (pOS2Header->ne_rsrctab) {
		LPBYTE pResourceTable = (((LPBYTE)pOS2Header)+pOS2Header->ne_rsrctab);
		DumpNEResourceTable(  dosHeader, pResourceTable);
		//MPanelItem* pChild = pRoot->AddFolder( "Resource Table"));
		//printf( "<Resource Table>\n"));
	}

	return true;
}
