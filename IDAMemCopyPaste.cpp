// IDAMemCopyPaste.cpp: implementation of the IDAMemCopyPaste class.
//
//////////////////////////////////////////////////////////////////////
//Standard Defs
typedef int     BOOL;
#define FALSE   0
#define TRUE    1
#define NULL    0

#include <pro.h>
#include <kernwin.hpp>
#include <bytes.hpp>
//#include <funcs.hpp>
//#include <lines.hpp>
//#include <name.hpp>
//#include <ida.hpp>
//#include <idp.hpp>
//#include <loader.hpp>

#include "IDAMemCopyPaste.h"//

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
//,Construction/Destruction
//////////////////////////////////////////////////////////////////////

IDAMemCopyPaste::IDAMemCopyPaste()
{
}

IDAMemCopyPaste::~IDAMemCopyPaste()
{

}
//////////////////////////////////////////////////////////////////////
// Helpers
//////////////////////////////////////////////////////////////////////

#define	MAX_COPYPASTE	1024

// This will hold our copied buffer for pasting
char data[MAX_COPYPASTE];

void IDAMemCopyPaste::copy_buffer(ea_t eaStartAddr, ea_t eaEndAddr) 
{
	ssize_t size;

	// Work out the size, make sure it doesn't exceed the buffer
	// we have allocated.
	size = eaEndAddr - eaStartAddr;
	if (size > MAX_COPYPASTE)
	{
		warning("You can only copy a max of %d bytes\n", MAX_COPYPASTE);
		return;
	}
	// Get the bytes from the file, store it in our buffer
	if (get_many_bytes(eaStartAddr, data, size)) 
	{
		msg("Successfully copied %d bytes from %a into memory.\n", size, eaStartAddr);
	}
	else
	{
		msg("FAILED to copy %d bytes from %a into memory.\n", size, eaStartAddr);
	}
}

void IDAMemCopyPaste::paste_buffer(ea_t eaStartAddr, ea_t eaEndAddr) 
{
	ssize_t size;

	// Work out the size, make sure it doesn't exceed the buffer
	// we have allocated.
	size = eaEndAddr - eaStartAddr;
	if (size > MAX_COPYPASTE)
	{
		warning("You can only copy a max of %d bytes\n", MAX_COPYPASTE);
		return;
	}
	// Patch the binary (paste)
	patch_many_bytes(eaStartAddr, data, size);
	msg("Patched %d bytes at %a.\n", size, eaStartAddr); 
}

//////////////////////////////////////////////////////////////////////
// Implementation
//////////////////////////////////////////////////////////////////////

//Looks for specific binary patterns and then makes a subroutine and comments it
void IDAMemCopyPaste::FindFuncSigsAndComment(void)
{

}