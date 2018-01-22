// BoschHelper.h: interface for the BoschHelper class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_BOSCHHELPER_H__9F97668B_19D4_4904_923E_1C391DF3A947__INCLUDED_)
#define AFX_BOSCHHELPER_H__9F97668B_19D4_4904_923E_1C391DF3A947__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "FunctionSigs.h"
#include <string>

using namespace std;

#define ROM_START	    0x800000
#define MAP_AREA_START	0x810000
#define MAP_AREA_FINISH	0x822000

class BoschHelper  : public FunctionSigs
{
public:
	BoschHelper();
	virtual ~BoschHelper();

	FunctionSigs functionsigsclass;
	sel_t mSelector;// Used to count the selector

	//helper functions
protected:
	bool CreateDissCode(ea_t eaStartAddr, ea_t eaEndAddr);// Loops through the binary and makes disassembled code
	bool BoschHelper::EnumDTCflags(ea_t eaStartAddr, ea_t eaEndAddr);// Loops through the binary and searches for where DTC flags are being set.
	bool SetC16xRegs(const char *RegName, sel_t value);// Sets the default register values on the C16x CPU
	bool CreateC16xSmallBoschSegments(ea_t eaStartAddr, ea_t eaEndAddr, char* cName, const char *sclass, sel_t dpp0, sel_t dpp1, sel_t dpp2, sel_t dpp3);// Creates a Bosch segment and default registers
	bool CreateC16xBoschSegments(ea_t eaParagraph, unsigned int iNumSegsToCreate, const char *sclass, sel_t dpp0, sel_t dpp1, sel_t dpp2, sel_t dpp3);// Creates the correct Bosch segments and default registers
	bool FindAndCreateArrayOffsets(ea_t eaStartAddr, ea_t eaEndAddr);// Loops through the binary and tries to make code offsets
	void MakeC166Offset(ea_t eaAddr, int nOp);//Makes C166 offsets utilising the correct DPP value
	bool FindAndCreateImplicitOffsets(ea_t eaStartAddr, ea_t eaEndAddr);

	//implementation
public:
	void MakeDissCode(string sECU);//Automatically disassembles the code and tries to make subroutines
	//void MakeSubroutines(void);//No longer used
	void MakeSegments(string sECU);//Makes the segments of the disassembly
	//void SearchForFuncSigs(BOOL bNewME711);//Looks for signatures of commonly known functions and set their name.
	void SearchForDTCFlagSetting(string sECU);//Looks for Bosch DTC setting fields.
	void SearchForFuncSigsAndThenCmt(string sECU);//Looks for specific binary patterns and then makes a subroutine and comments it
	void SearchForArrayOffsetsAndThenCreate(string sECU);//Looks for instructions that will probably contain an offset. When found it creates them.
};

#endif // !defined(AFX_BOSCHHELPER_H__9F97668B_19D4_4904_923E_1C391DF3A947__INCLUDED_)
