//==================================
// PEDUMP - Matt Pietrek 1997-2001
// FILE: OBJDUMP.CPP
//==================================

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include "common.h"
#include "SymbolTableSupport.h"
#include "COFFSymbolTable.h"
#include "extrnvar.h"

struct RelocTypes
{
    WORD type;
    PSTR name;
};

// ASCII names for the various relocations used in i386 COFF OBJs
RelocTypes s_i386Relocations[] = 
{
{ IMAGE_REL_I386_ABSOLUTE, (PSTR) "ABSOLUTE" },
{ IMAGE_REL_I386_DIR16, (PSTR) "DIR16" },
{ IMAGE_REL_I386_REL16, (PSTR) "REL16" },
{ IMAGE_REL_I386_DIR32, (PSTR) "DIR32" },
{ IMAGE_REL_I386_DIR32NB, (PSTR) "DIR32NB" },
{ IMAGE_REL_I386_SEG12, (PSTR) "SEG12" },
{ IMAGE_REL_I386_SECTION, (PSTR) "SECTION" },
{ IMAGE_REL_I386_SECREL, (PSTR) "SECREL" },
{ IMAGE_REL_I386_REL32, (PSTR) "REL32" },
{ 0xC, (PSTR) "CLRTOKEN" },	// Matt added this, although not yet defined in WINNT.H
};
#define I386RELOCTYPECOUNT (sizeof(s_i386Relocations) / sizeof(RelocTypes))

RelocTypes s_IA64Relocations[] = 
{
{ IMAGE_REL_IA64_ABSOLUTE, (PSTR) "ABSOLUTE" },
{ IMAGE_REL_IA64_IMM14, (PSTR) "IMM14" },
{ IMAGE_REL_IA64_IMM22, (PSTR) "IMM22" },
{ IMAGE_REL_IA64_IMM64, (PSTR) "IMM64" },
{ IMAGE_REL_IA64_DIR32, (PSTR) "DIR32" },
{ IMAGE_REL_IA64_DIR64, (PSTR) "DIR64" },
{ IMAGE_REL_IA64_PCREL21B, (PSTR) "PCREL21B" },
{ IMAGE_REL_IA64_PCREL21M, (PSTR) "PCREL21M" },
{ IMAGE_REL_IA64_PCREL21F, (PSTR) "PCREL21F" },
{ IMAGE_REL_IA64_GPREL22, (PSTR) "GPREL22" },
{ IMAGE_REL_IA64_LTOFF22, (PSTR) "LTOFF22" },
{ IMAGE_REL_IA64_SECTION, (PSTR) "SECTION" },
{ IMAGE_REL_IA64_SECREL22, (PSTR) "SECREL22" },
{ IMAGE_REL_IA64_SECREL64I, (PSTR) "SECREL64I" },
{ IMAGE_REL_IA64_SECREL32, (PSTR) "SECREL32" },
// { IMAGE_REL_IA64_LTOFF64", (PSTR) "LTOFF64" },
{ IMAGE_REL_IA64_DIR32NB, (PSTR) "DIR32NB" },
{ IMAGE_REL_IA64_SREL14, (PSTR) "SREL14" },
{ IMAGE_REL_IA64_SREL22, (PSTR) "SREL22" },
{ IMAGE_REL_IA64_SREL32, (PSTR) "SREL32" },
{ IMAGE_REL_IA64_UREL32, (PSTR) "UREL32" },
{ IMAGE_REL_IA64_PCREL60X, (PSTR) "PCREL60X" },
{ IMAGE_REL_IA64_PCREL60B, (PSTR) "PCREL60B" },
{ IMAGE_REL_IA64_PCREL60F, (PSTR) "PCREL60F" },
{ IMAGE_REL_IA64_PCREL60I, (PSTR) "PCREL60I" },
{ IMAGE_REL_IA64_PCREL60M, (PSTR) "PCREL60M" },
{ IMAGE_REL_IA64_IMMGPREL64, (PSTR) "IMMGPREL64" },
{ IMAGE_REL_IA64_TOKEN, (PSTR) "TOKEN" },
{ IMAGE_REL_IA64_GPREL32, (PSTR) "GPREL32" },
{ IMAGE_REL_IA64_ADDEND, (PSTR) "ADDEND" },
};
#define IA64RELOCTYPECOUNT (sizeof(s_IA64Relocations) / sizeof(RelocTypes))

//
// Given an i386 OBJ relocation type, return its ASCII name in a buffer
//
void GetObjRelocationName(WORD machine, WORD type, PSTR buffer, DWORD cBytes)
{
    DWORD i;

    if ( IMAGE_FILE_MACHINE_I386 == machine )
	{
		for ( i=0; i < I386RELOCTYPECOUNT; i++ )
			if ( type == s_i386Relocations[i].type )
			{
				strncpy(buffer, s_i386Relocations[i].name, cBytes);
				return;
			}
    }
	else if ( IMAGE_FILE_MACHINE_IA64 == machine )
	{
		for ( i=0; i < IA64RELOCTYPECOUNT; i++ )
			if ( type == s_IA64Relocations[i].type )
			{
				strncpy(buffer, s_IA64Relocations[i].name, cBytes);
				return;
			}

	}
    
    sprintf( buffer, "???_%X", type);
}

//
// Dump the relocation table for one COFF section
//
void DumpObjRelocations(   WORD machine, PIMAGE_RELOCATION pRelocs, DWORD count )
{
    DWORD i;
    char szTypeName[32];
    
    for ( i=0; i < count; i++ )
    {
        GetObjRelocationName(machine, pRelocs->Type, szTypeName, sizeof(szTypeName));
        printf("  Address: %08X  SymIndex: %08X  Type: %s\n",
                pRelocs->VirtualAddress, pRelocs->SymbolTableIndex,
                szTypeName);
        pRelocs++;
    }
}

//
// top level routine called from PEDUMP.C to dump the components of a
// COFF OBJ file.
//
bool DumpObjFile(   PIMAGE_FILE_HEADER pImageFileHeader )
{
    unsigned i;
    PIMAGE_SECTION_HEADER pSections;
    
    DumpHeader(  pImageFileHeader);
    printf("\n");

    pSections = MakePtr(PIMAGE_SECTION_HEADER, (pImageFileHeader+1),
                            pImageFileHeader->SizeOfOptionalHeader);

    DumpSectionTable(  pSections, pImageFileHeader->NumberOfSections, FALSE);
    printf("\n");

    if ( fShowRelocations )
    {
        for ( i=0; i < pImageFileHeader->NumberOfSections; i++ )
        {
            if ( pSections[i].PointerToRelocations == 0 )
                continue;
        
            printf("Section %02X (%.8s) relocations\n", i+1, pSections[i].Name);
            DumpObjRelocations(	  pImageFileHeader->Machine,
								MakePtr(PIMAGE_RELOCATION, pImageFileHeader, pSections[i].PointerToRelocations),
                                pSections[i].NumberOfRelocations );
            printf("\n");
        }
    }
     
    if ( fShowSymbolTable && pImageFileHeader->PointerToSymbolTable )
    {
		g_pCOFFSymbolTable = new COFFSymbolTable(
					MakePtr(PVOID, pImageFileHeader, 
							pImageFileHeader->PointerToSymbolTable),
					pImageFileHeader->NumberOfSymbols );

        DumpCOFFSymbolTable(   g_pCOFFSymbolTable );

        printf("\n");
    }

    if ( fShowLineNumbers )
    {
        // Walk through the section table...
        for (i=0; i < pImageFileHeader->NumberOfSections; i++)
        {
            // if there's any line numbers for this section, dump'em
            if ( pSections->NumberOfLinenumbers )
            {
                DumpLineNumbers(   MakePtr(PIMAGE_LINENUMBER, pImageFileHeader,
                                         pSections->PointerToLinenumbers),
                                 pSections->NumberOfLinenumbers );
                printf("\n");
            }
            pSections++;
        }
    }
    
    if ( fShowRawSectionData )
    {
        DumpRawSectionData(   (PIMAGE_SECTION_HEADER)(pImageFileHeader+1),
                            pImageFileHeader,
                            pImageFileHeader->NumberOfSections);
    }

	delete g_pCOFFSymbolTable;
	return true;
}
