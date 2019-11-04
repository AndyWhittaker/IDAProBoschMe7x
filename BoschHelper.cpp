// BoschHelper.cpp: implementation of the BoschHelper class.
//
//////////////////////////////////////////////////////////////////////
//Standard Defs
typedef int     BOOL;
#define FALSE   0
#define TRUE    1
#define NULL    0

#include <ida.hpp>
#include <idp.hpp>//str2reg()
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <offset.hpp>
#include <search.hpp>
#include <segregs.hpp> //SetDefaultRegisterValue()
#include <allins.hpp> // processor instructions
#include <funcs.hpp> //get_func()
#include <enum.hpp> //for enumerations
#include <auto.hpp> // for showaddr

#include "BoschHelper.h"
//#include "FunctionSigs.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

BoschHelper::BoschHelper()
{
	mSelector = 1;

}

BoschHelper::~BoschHelper()
{

}


//////////////////////////////////////////////////////////////////////
// Helpers
//////////////////////////////////////////////////////////////////////

// Loops through the binary and makes disassembled code
bool BoschHelper::CreateDissCode(ea_t eaStartAddr, ea_t eaEndAddr)
{
	msg("Creating disassembly from 0x%x through to 0x%x\n", eaStartAddr, eaEndAddr);

	ea_t	eaAddr, eaLenOfGeneratedCode;
	int		iCount, iReturns;
	ushort	uWord;

	eaAddr = eaStartAddr;
	eaLenOfGeneratedCode = 1;
	iCount = iReturns = 1;

	show_wait_box("Creating disassembly...");
	for (eaAddr; eaAddr<eaEndAddr; eaAddr += eaLenOfGeneratedCode)
	{
		if ((eaAddr % 0x1000) == 0)
		{
			show_addr(eaAddr);
			if (user_cancelled())
				break;
		}

		//guard against disassembling 0xffff or 0x0000 pairs
		uWord = static_cast<ushort>(get_16bit(eaAddr));//read the word at the current location
		
		if(uWord == 0xffff)
		{
//			msg("0xffff read at 0x%x\n", eaAddr);
			create_word(eaAddr, 4);//Convert to data word
			eaAddr+=1;//skip these bytes
		}
		else if(uWord == 0x0000)
		{
//			msg("0x0000 read at 0x%x\n", eaAddr);
			create_word(eaAddr, 4);//Convert to data word
			eaAddr+=1;//skip these bytes
		}
		else if(uWord == 0x8000)
		{
//			msg("0x8000 read at 0x%x\n", eaAddr);
			create_word(eaAddr, 4);//Convert to data word
			eaAddr+=1;//skip these bytes
		}
		else
		{
			//attempt to disassemble the next code
			eaLenOfGeneratedCode = create_insn(eaAddr);//create the disassembled code and return the length of it
			//msg("Code created at 0x%X\n", eaAddr);
			if(eaLenOfGeneratedCode == 0)
			{//guard against nothing happening
				eaLenOfGeneratedCode++;
			}
			else if(iCount >= 0x200)
			{
				iCount=0;
				msg(".");
			}
			else if(iReturns >= 0x4000)
			{
				iReturns=0;
				msg("\n");
			}
		}
	}
	msg("\n");
	hide_wait_box();

	msg("Looking through code to make subroutines....\n");
	//
	// Look for subroutines within the code
	//

	eaAddr = eaStartAddr;
	eaLenOfGeneratedCode = 1;
	iCount = iReturns = 1;

	// Instructions we know that subroutines don't start with.
	int instrs[] = { C166_jmps, C166_jmpr, C166_ret, C166_reti, C166_retp, C166_rets, C166_rol, C166_add, C166_shr, C166_xor, C166_xorb, 0 };
	qstring mnem;
	const char *res;
	bool	bFound;

	show_wait_box("Making subroutines...");
	for (eaAddr; eaAddr<eaEndAddr;)
	{
		if ((eaAddr % 0x100) == 0)
		{
			show_addr(eaAddr);
			if (user_cancelled())
				break;
		}

		//Create a function if possible but ignore certain instructions
		//because we know functions will not start with them
		bFound = false;

		//Get the mnemonic at this address
		insn_t cmd;
		decode_insn(&cmd, eaAddr);

		// Check the mnemonic of this address against all
		// mnemonics we're interested in.
		for (int i = 0; instrs[i] != 0; i++)
		{
			
			if (cmd.itype == instrs[i])
			{
				bFound = true;
			}
		}

		if(!bFound)
		{
			if(add_func(eaAddr, BADADDR))
			{
				msg("Function created at %x\n", eaAddr);
				func_t *func = get_func(eaAddr);
				if (func != NULL)
				{
					eaAddr += (func->end_ea - func->start_ea);
				}
				else
				{
					eaAddr++;
				}
			}
			else
			{
				eaAddr++;
			}
		}
		else
		{
			eaAddr++;
		}
	}
	hide_wait_box();
	return true;
}

// Loops through the binary and searches for where DTC flags are being set.
bool BoschHelper::EnumDTCflags(ea_t eaStartAddr, ea_t eaEndAddr)
{
	msg("Searching for DTC setting flags from 0x%x through to 0x%x\n", eaStartAddr, eaEndAddr);

	// Instructions we know that DTC setting is done by.
	qstring mnem;
//	uval_t		uvalOp1Value, uvalOp2Value;

	ea_t	eaAddr;

	eaAddr = eaStartAddr;// sets the start

	show_wait_box("Searching for DTCs...");
	for (eaAddr; eaAddr<eaEndAddr;)
	{
		if ((eaAddr % 0x100) == 0)
		{
			show_addr(eaAddr);
			if (user_cancelled())
				break;
		}

		// Get the flags for this address
		flags_t flags = get_flags(eaAddr);

		// Only look at the address if it's a head byte, i.e.
		// the start of an instruction and is code.
		if (is_head(flags) && is_code(flags))
		{
			//char mnem[MAXSTR];

			//Get the mnemonic at this address
			
			insn_t cmd;
			decode_insn(&cmd, eaAddr);
			// Check the mnemonic of this address against all
			// mnemonics we're interested in.

			if(cmd.itype == C166_bfldh)//We've found the instruction we're interested in.
			{
				msg("bfldh found at 0x%x\n", eaAddr);

				//we've found the instruction we're interested in.
				//get_operand_immvals(eaAddr, 1, &uvalOp1Value);
				//get_operand_immvals(eaAddr, 2, &uvalOp2Value);

				//msg("Instruction Len 0x%x : Op1 Value 0x%x : Op2 Value 0x%x\n", cmd.size, uvalOp1Value, uvalOp2Value);

				op_enum(eaAddr, 1, get_enum("DTCHBit"), NULL);

				eaAddr+= cmd.size;//next instruction
			}
			else if(cmd.itype == C166_bfldl)//We've found the instruction we're interested in.
			{
				msg("bfldl found at 0x%x\n", eaAddr);

				//we've found the instruction we're interested in.
				//get_operand_immvals(eaAddr, 1, &uvalOp1Value);
				//get_operand_immvals(eaAddr, 2, &uvalOp2Value);

				op_enum(eaAddr, 1, get_enum("DTCLBit"), NULL);

				eaAddr+= cmd.size;//next instruction
			}
			else
				eaAddr++;
		}
		else
			eaAddr++;
	}
	hide_wait_box();
	return 1;
}

// Sets the default register values on the C16x CPU
bool BoschHelper::SetC16xRegs(const char *szRegName, sel_t value)
{
	int		iReg;

	iReg = str2reg(szRegName);
	msg("Setting register %s, number %i to %x", szRegName, iReg, value);
	if (set_default_sreg_value(nullptr, iReg, value))
		msg(" successful.\n");
	else
	{
		msg(" failed.\n");
		return 0;
	}
	return 1;
}

// Creates a Bosch segment and default registers
bool BoschHelper::CreateC16xSmallBoschSegments(ea_t eaStartAddr, ea_t eaEndAddr, char* cName, const char *sclass, sel_t dpp0, sel_t dpp1, sel_t dpp2, sel_t dpp3)
{
	char	cBuf[20];
	ea_t	eaParagraph;

	msg("\nBoschHelper::CreateC16xSmallBoschSegments Started\n");
//	msg("Deleting Segments\n");
//	del_segm(eaStartAddr, SEGDEL_KEEP);
	::qsnprintf(cBuf, 17, "%s", cName);
	eaParagraph = eaStartAddr >> 4;// divide by 16
	msg("Creating segment at para %x, start address %x, end address %x, name %s, selector 0x%x\n", eaParagraph, eaStartAddr, eaEndAddr, cBuf, mSelector);
	set_selector(mSelector, eaParagraph);
//	set_selector(mSelector, 0);
	mSelector++;
	msg("Adding new segments\n");
	add_segm(eaParagraph, eaStartAddr, eaEndAddr, cBuf, sclass);

	//Set the default register values for this segment
	msg("Setting DPPs\n");
	SetC16xRegs("dpp0", dpp0);
	SetC16xRegs("dpp1", dpp1);
	SetC16xRegs("dpp2", dpp2);
	SetC16xRegs("dpp3", dpp3);
	msg("BoschHelper::CreateC16xSmallBoschSegments Finished\n");
	return 1;
}

// Creates the correct Bosch segments and default registers
bool BoschHelper::CreateC16xBoschSegments(ea_t eaParagraph, unsigned int iNumSegsToCreate, const char *sclass, sel_t dpp0, sel_t dpp1, sel_t dpp2, sel_t dpp3)
{
	sel_t	selSelector = 0;
	ea_t	eaStartAddr, eaEndAddr;
	int		iDPPNum;
	char	cBuf[20];

	msg("\nBoschHelper::CreateC16xBoschSegments Started\n");
	for(selSelector; selSelector<iNumSegsToCreate; selSelector++)
	{
		eaStartAddr = (eaParagraph * 0x10) + (selSelector * 0x4000);
		eaEndAddr = eaStartAddr + 0x4000;
		iDPPNum = eaStartAddr / 0x4000;//gets the dpp equivalent for the segment label
		qsnprintf(cBuf, 17, "Seg0x%x@%x", iDPPNum, eaStartAddr);
		msg("Creating segment at para %x, start address %x, end address %x, name %s, selector 0x%x\n", eaParagraph, eaStartAddr, eaEndAddr, cBuf, mSelector);
		set_selector(mSelector, eaParagraph);
//		set_selector(mSelector, 0);
		mSelector++;
		add_segm(eaParagraph, eaStartAddr, eaEndAddr, cBuf, sclass);

		//Set the default register values for this segment
		msg("Setting DPPs\n");
		SetC16xRegs("dpp0", dpp0);
		SetC16xRegs("dpp1", dpp1);
		SetC16xRegs("dpp2", dpp2);
		SetC16xRegs("dpp3", dpp3);
	}
	msg("BoschHelper::CreateC16xBoschSegments Finished\n");
	return 1;
}

// Loops through the binary and tries to make code offsets from arrays
// e.g. movb    [r5+0E0A4h], rl4 = movb    [r5+word_E0A4], rl4
bool BoschHelper::FindAndCreateArrayOffsets(ea_t eaStartAddr, ea_t eaEndAddr)
{
	msg("Finding array offsets and trying to create them from 0x%x through to 0x%x\n", eaStartAddr, eaEndAddr);

	ea_t	eaAddr, eaLenOfGeneratedCode;
	int		iCount, iReturns;

	//
	// Look for known function that will contain offsets within the code
	//

	eaAddr = eaStartAddr;
	eaLenOfGeneratedCode = 1;
	iCount = iReturns = 1;

	// Instructions we know that contain arrays.
	int instrs[] = { C166_mov, C166_movb, 0 };
	qstring mnem;
	qstring res;
	bool	bFound;

	show_wait_box("Searching for array offsets...");

	for (eaAddr; eaAddr<eaEndAddr;)
	{
		//Find instructions we know will have offsets in them
		bFound = 0;

		if ((eaAddr % 0x100) == 0)
		{
			show_addr(eaAddr);
			if (user_cancelled())
				break;
		}

		//Get the flags for this address
		flags_t flags = get_flags(eaAddr);

		//Only look at the address if it's a head byte
		//i.e. the start of an instruction and its code
		if(is_head(flags) && is_code(flags))
		{
			//Get the mnemonic at this address
			insn_t cmd;
			decode_insn(&cmd, eaAddr);

			// Check the mnemonic of this address against all
			// mnemonics we're interested in.
			for (int i = 0; instrs[i] != 0; i++)
			{
				if (cmd.itype == instrs[i])
				{
					bFound = 1;
				}
			}
			//We have an instruction we're interested in
			if(bFound)
			{
				//check the type of mnemonic.
/*				msg("Instruction mnemonic at 0x%x :->\n", eaAddr);
				msg("    Op0: n = %d type = %d reg = %d value = %a addr = %a\n",
					cmd.Operands[0].n,
					cmd.Operands[0].type,
					cmd.Operands[0].reg,
					cmd.Operands[0].value,
					cmd.Operands[0].addr);
				msg("    Op1: n = %d type = %d reg = %d value = %a addr = %a\n",
					cmd.Operands[1].n,
					cmd.Operands[1].type,
					cmd.Operands[1].reg,
					cmd.Operands[1].value,
					cmd.Operands[1].addr);
*/				
				// Is the instruction Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr?
				// If so, then these need converting into offset addresses
				if(cmd.ops[0].type == o_displ)
				{
					//r0 is a special register and should not be offsetted
					if(cmd.ops[0].reg!= 0)
						if(cmd.ops[0].addr >= 0x00ff)
							MakeC166Offset(eaAddr, 0);
				}
				else if(cmd.ops[1].type == o_displ)
				{
					//r0 is a special register and should not be offsetted
					if(cmd.ops[1].reg!= 0)
						if(cmd.ops[1].addr >= 0x00ff)
							MakeC166Offset(eaAddr, 1);
				}
			}
		}
		eaAddr++;
	}
	hide_wait_box();
	return 1;
}

//Makes C166 offsets utilising the correct DPP value
// eaAddr = Address of the instruction
// nOp = Operand Number
void BoschHelper::MakeC166Offset(ea_t eaAddr, int nOp)
{
	//Translate the address we get into a real address
	int		iReg;
	ea_t	eaDpp;
	sel_t	selSelector;
					

	insn_t cmd;
	decode_insn(&cmd, eaAddr);

	//Find out what DPP the address we've found lives in.
	//The DPP selector is the top two bits
	eaDpp = (cmd.ops[1].addr & 0xc000) >> 14;
	if(eaDpp == 0)
	{
		iReg = str2reg("DPP0");
	}
	else if (eaDpp==1)
	{
		iReg = str2reg("DPP1");
	}
	else if (eaDpp==2)
	{
		iReg = str2reg("DPP2");
	}
	else
	{
		iReg = str2reg("DPP3");
	}
	//Get the value of the selected register
	//Don't ask me why but the register needs to be multiplied by 16 to become the base
	selSelector = get_sreg(eaAddr, iReg) << 4;
	ea_t eaOffsetBase = get_offbase(eaAddr, nOp);//For information, not used
	msg("**** At address 0x%x DPP number 0x%x for Register 0x%x, is 0x%x. Op is 0x%x. Offset base is 0x%x\n", eaAddr, eaDpp, iReg, selSelector, nOp, eaOffsetBase);
	//Create the offset
	if(op_offset(eaAddr, nOp, REF_OFF16, BADADDR, selSelector) == 0)
	{
		msg("op_offset failed\n");
	}
}

// Loops through the binary and tries to make code offsets from implicit references
// e.g. movb    [r5+0E0A4h], rl4 = movb    [r5+word_E0A4], rl4
//mov     r4, #0F9F6h     ; Move Word <- Here's the address
//mov     r5, #0          ; Move Word <- Here's the segment
//movbz   r2, rl6         ; Move Byte Zero Extend
//shl     r2, #1          ; Shift Left
//mov     r3, #0          ; Move Word
//add     r4, r2          ; Integer Addition
//addc    r5, r3          ; Integer Addition with Carry
//exts    r5, #1          ; Begin Extended Segment Sequence <- This requires a segment
//mov     r12, [r4]       ; Move Word with phrase <- This requires an address
bool BoschHelper::FindAndCreateImplicitOffsets(ea_t eaStartAddr, ea_t eaEndAddr)
{
	msg("Finding implicit offsets and trying to create them from 0x%x through to 0x%x\n", eaStartAddr, eaEndAddr);

	ea_t	eaAddr, eaLenOfGeneratedCode;
	int		iCount, iReturns;

	//
	// Look for known function that will contain offsets within the code
	//

	eaAddr = eaStartAddr;
	eaLenOfGeneratedCode = 1;
	iCount = iReturns = 1;

	// Instructions we know that contain addresses.
	int instrs[] = { C166_mov, 0 };
	qstring mnem;
	bool bFound;

	show_wait_box("Searching for implicit offsets...");

	for (eaAddr; eaAddr<eaEndAddr;)
	{
		//Find instructions we know will have offsets in them
		bFound = 0;

		if ((eaAddr % 0x100) == 0)
		{
			show_addr(eaAddr);
			if (user_cancelled())
				break;
		}

		//Get the flags for this address
		flags_t flags = get_flags(eaAddr);

		//Only look at the address if it's a head byte
		//i.e. the start of an instruction and its code
		if(is_head(flags) && is_code(flags))
		{
			//Get the mnemonic at this address
			insn_t cmd;
			decode_insn(&cmd, eaAddr);

			// Check the mnemonic of this address against all
			// mnemonics we're interested in.
			for (int i = 0; instrs[i] != 0; i++)
			{
				if (cmd.itype == instrs[i])
				{
					bFound = 1;
				}
			}
			//We have an instruction we're interested in
			if(bFound)
			{
				//check the type of mnemonic.
				msg("Instruction mnemonic at 0x%x :->\n", eaAddr);
				msg("    Op0: n = %d type = %d reg = %d value = %a addr = %a\n",
					cmd.ops[0].n,
					cmd.ops[0].type,
					cmd.ops[0].reg,
					cmd.ops[0].value,
					cmd.ops[0].addr);
				msg("    Op1: n = %d type = %d reg = %d value = %a addr = %a\n",
					cmd.ops[1].n,
					cmd.ops[1].type,
					cmd.ops[1].reg,
					cmd.ops[1].value,
					cmd.ops[1].addr);
				
				// Is the instruction a Memory Ref [Base Reg + Index Reg] and not r0?
				// If so, then we need to back track and see when it's loaded with an immediate
				// Need to do this for cmd.Operands[0] and cmd.Operands[1]
				// Also backtrack one instruction and see if there's a "exts"
				if((cmd.ops[1].type == o_phrase) & (cmd.ops[1].reg != 0))
				{
					msg("We're at a phrase and need to look for where r%a was immediate loaded.\n", cmd.ops[1].reg);
					// We need to backtrack & find where this register was loaded immediate at op1

					//r0 is a special register and should not be offsetted
//					if(cmd.Operands[1].reg!= 0)
//						if(cmd.Operands[1].addr >= 0x00ff)
//							MakeC166Offset(eaAddr, 1);
				}
			}
		}
		eaAddr++;
	}
	hide_wait_box();
	return 1;
}

//////////////////////////////////////////////////////////////////////
// Implementation
//////////////////////////////////////////////////////////////////////

//Automatically disassembles the code and tries to make subroutines
void BoschHelper::MakeDissCode(string sECU)
{
	if(sECU == "bNewME711")
	{
		CreateDissCode(0x00000, 0xdfff);
		CreateDissCode(0x10000, 0xcffff);
		//CreateDissCode(0x800014, 0x803422);
		CreateDissCode(0x800014, 0x8fffff);
		//CreateDissCode(0x800014, 0x80ffff);
		//RAM is @ 0x380000 - 0x383fff - size 0x4000
		//Data is @0x8
		CreateDissCode(0x81e28c, 0x81ea40);
	}
	else if (sECU == "ME761Astra")
	{
		CreateDissCode(0x0000, 0x3fff);
		CreateDissCode(0x4000, 0x7fff);
		CreateDissCode(0x10000, 0xaffff);
		CreateDissCode(0xc0000, 0xcff00);
	}
	else
	{
		CreateDissCode(0x00000, 0x1ff);
		CreateDissCode(0x700, 0x7fff);
		CreateDissCode(0x800000, 0x810000);
		CreateDissCode(0x830000, 0x8fff00);
	}
}

//No longer used
//void BoschHelper::MakeSubroutines(void)
//{
//	ea_t	eaResult=0, eaLast=0;
//
//	add_func(eaResult, BADADDR);
//
//	while(eaResult != BADADDR)
//	{
//		eaResult = find_unknown(eaLast, SEARCH_DOWN);
//		if(add_func(eaResult, BADADDR))
//			msg("Function created at %x\n", eaResult);
//
//		if( (eaResult > MAP_AREA_START) & (eaResult < MAP_AREA_FINISH) )
//		{
//			msg("Ignoring data - within MAP area\n");
//			eaResult = MAP_AREA_FINISH;
//		}
//		if(eaResult == BADADDR)
//			msg("End of Auto-Disassemble analysis loop\n");
//
//		eaLast = eaResult;
//	}
//
//}

//Makes the segments of the disassembly
//void BoschHelper::MakeSegments(BOOL bNewME711)
void BoschHelper::MakeSegments(string sECU)
{
	//bool BoschHelper::CreateC16xBoschSegments(ea_t eaParagraph, unsigned int iNumSegsToCreate, const char *sclass, sel_t dpp0, sel_t dpp1, sel_t dpp2, sel_t dpp3)
	if(sECU == "bNewME711")
	{
		//CreateC16xBoschSegments(0x0000, 4, "ABS", 0x0, 0x1, 2, 3);
		CreateC16xSmallBoschSegments(0x0000, 0x8000, "MEM_EXT", "CODE", 0x23f, 0x3c, 0x0e0, 3);
		//SFR
		CreateC16xSmallBoschSegments(0x8000, 0xE000, "MEM_EXT", "CODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xSmallBoschSegments(0xE000, 0xE800, "XRAM", "DATA", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xSmallBoschSegments(0xE800, 0xEf00, "RESERVED", "BSS", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xSmallBoschSegments(0xEf00, 0xf000, "CAN1", "DATA", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xSmallBoschSegments(0xf000, 0xf200, "E_SFR", "DATA", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xSmallBoschSegments(0xf200, 0xf600, "RESERVED", "BSS", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xSmallBoschSegments(0xf600, 0xfE00, "IRAM", "CODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xSmallBoschSegments(0xfe00, 0x10000, "SFR", "DATA", 0x23f, 0x3c, 0x0e0, 3);

		//MPU ROM
		CreateC16xBoschSegments(0x1000, 4, "MPUCODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0x2000, 4, "MPUCODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0x3000, 4, "MPUCODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0x4000, 4, "MPUCODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0x5000, 4, "MPUCODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0x6000, 4, "MPUCODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0x7000, 4, "MPUCODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0x8000, 4, "MPUCODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0x9000, 4, "MPUCODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0xa000, 4, "MPUCODE", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0xb000, 4, "DATA", 0x23f, 0x3c, 0x0e0, 3);
		CreateC16xBoschSegments(0xc000, 4, "DATA", 0x23f, 0x3c, 0x0e0, 3);

		//RAM
		CreateC16xBoschSegments(0xe000, 4, "CODERAM", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0xf000, 4, "CODERAM", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x38000, 4, "DATARAM", 0x23f, 0x3c, 0xe0, 3);

		//ROM
		CreateC16xBoschSegments(0x80000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x81000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x82000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x83000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x84000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x85000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x86000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x87000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x88000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x89000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x8a000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x8b000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x8c000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x8d000, 4, "CODE", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x8e000, 4, "DATA", 0x23f, 0x3c, 0xe0, 3);
		CreateC16xBoschSegments(0x8f000, 4, "DATA", 0x23f, 0x3c, 0xe0, 3);
	}
	else if (sECU == "ME761Astra")
	{
		CreateC16xSmallBoschSegments(0x0000, 0x8000, "MEM_EXT", "CODE", 0x0, 0x1, 0x2, 0x3);
		//SFR
		CreateC16xSmallBoschSegments(0x8000, 0xE000, "MEM_EXT", "CODE", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xE000, 0xE800, "XRAM", "DATA", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xE800, 0xEf00, "RESERVED", "BSS", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xEf00, 0xf000, "CAN1", "DATA", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xf000, 0xf200, "E_SFR", "DATA", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xf200, 0xf600, "RESERVED", "BSS", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xf600, 0xfE00, "IRAM", "CODE", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xfe00, 0x10000, "SFR", "DATA", 0x0, 0x1, 0x2, 0x3);
		//RAM
		CreateC16xBoschSegments(0xf000, 4, "DATA" , 0x2c, 0x2d, 0x3c, 3);
		//ROM
		CreateC16xBoschSegments(0x1000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0x2000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0x3000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0x4000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0x5000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0x6000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0x7000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0x8000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0x9000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0xa000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0xb000, 4, "DATA", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0xc000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
		CreateC16xBoschSegments(0xd000, 4, "CODE", 0x2c, 0x2d, 0x3c, 3);
	}
	else
	{
		CreateC16xSmallBoschSegments(0x0000, 0x8000, "MEM_EXT", "CODE", 0x0, 0x1, 0x2, 0x3);
		//SFR
		CreateC16xSmallBoschSegments(0x8000, 0xE000, "MEM_EXT", "CODE", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xE000, 0xE800, "XRAM", "DATA", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xE800, 0xEf00, "RESERVED", "BSS", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xEf00, 0xf000, "CAN1", "DATA", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xf000, 0xf200, "E_SFR", "DATA", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xf200, 0xf600, "RESERVED", "BSS", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xf600, 0xfE00, "IRAM", "CODE", 0x0, 0x1, 0x2, 0x3);
		CreateC16xSmallBoschSegments(0xfe00, 0x10000, "SFR", "DATA", 0x0, 0x1, 0x2, 0x3);
		//RAM
		CreateC16xBoschSegments(0x38000, 2, "DATA" , 0x204, 0x205, 0xe0, 3);
		//ROM
		CreateC16xBoschSegments(0x80000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x81000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x82000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x83000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x84000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x85000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x86000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x87000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x88000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x89000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x8a000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x8b000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x8c000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x8d000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x8e000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
		CreateC16xBoschSegments(0x8f000, 4, "CODE", 0x204, 0x205, 0xe0, 3);
	}
}

//Looks for signatures of commonly known functions and set their name.
//Test routine!
//void BoschHelper::SearchForFuncSigs(BOOL bNewME711)
//{
//	//No longer used
//	const uchar	test[]={0xfa, 0x82, 0xd8, 0x00, 0xfa, 0xff, 0xDC, 0x00};
//	ea_t	eaFound;
//
//	eaFound = FindBinaryWithDontCare((uchar*)test, 8, 0x800000, 0x80ffff);
//	if(eaFound != BADADDR)
//		msg("Found Sig at 0x%x\n", eaFound);
//	else
//		msg("Sig not found\n");
//}

//Looks for Bosch DTC setting fields.
void BoschHelper::SearchForDTCFlagSetting(string sECU)
{
	//Create the enum constants first
	enum_t	enumtID;

	//The DTC enum for low bits
	enumtID = add_enum(BADADDR, "DTCLBit", 0x1100000);//Create the enum
	set_enum_bf(enumtID, 1);//Set the enum to a bitfield
	//Now fill the enum structure
	add_enum_member(enumtID,"DTCBit_L0",	0x1,	0x1);
	add_enum_member(enumtID,"DTCBit_L1",	0x2,	0x2);
	add_enum_member(enumtID,"DTCBit_L2",	0x4,	0x4);
	add_enum_member(enumtID,"DTCBit_L3",	0x8,	0x8);
	add_enum_member(enumtID,"DTCBit_L4",	0x10,	0x10);
	add_enum_member(enumtID,"DTCBit_L5",	0x20,	0x20);
	add_enum_member(enumtID,"DTCBit_L6",	0x40,	0x40);
	add_enum_member(enumtID,"DTCBit_L7",	0x80,	0x80);

	//The DTC enum for high bits
	enumtID = add_enum(BADADDR, "DTCHBit", 0x1100000);//Create the enum
	set_enum_bf(enumtID, 1);//Set the enum to a bitfield
	//Now fill the enum structure
	add_enum_member(enumtID,"DTCFieldA_H0",	0x1,	0x1);
	// TODO-STHO set_enum_cmt(get_const(enumtID, 0x1, NULL, 0x1),"Select DTC Group A",1);
	//set_enum_cmt(get_const(enumtID, 0x1, NULL, 0x1), "Select DTC Group A", 1);
	add_enum_member(enumtID, "DTCFieldB_H1", 0x2, 0x2);
	// TODO-STHO set_enum_cmt(get_const(enumtID, 0x2, NULL, 0x2),"Select DTC Group B",1);
	add_enum_member(enumtID,"DTCFieldC_H2",	0x4,	0x4);
	// TODO-STHO set_enum_cmt(get_const(enumtID, 0x4, NULL, 0x4),"Select DTC Group C",1);
	add_enum_member(enumtID,"DTCFieldD_H3",	0x8,	0x8);
	// TODO-STHO set_enum_cmt(get_const(enumtID, 0x8, NULL, 0x8),"Select DTC Group D",1);
	add_enum_member(enumtID,"DTCBit_H4",	0x10,	0x10);
	add_enum_member(enumtID,"DTCBit_H5",	0x20,	0x20);
	add_enum_member(enumtID,"DTCBit_H6",	0x40,	0x40);
	add_enum_member(enumtID,"DTCBit_H7",	0x80,	0x80);

	//Search the disassembly for enum flag setting
	if(sECU == "bNewME711")
	{
		EnumDTCflags(0x00000, 0xffffff);
	}
	else if (sECU == "ME761Astra")
	{
		EnumDTCflags(0x10000, 0xff000);
	}
	else
	{
		EnumDTCflags(0x820000, 0x8ff000);
	}
}

//Looks for specific binary patterns and then makes a subroutine and comments it
void BoschHelper::SearchForFuncSigsAndThenCmt(string sECU)
{
	if (sECU == "ME761Astra")
	{
		msg("**s* ME761Astra 1st pass\n");
		functionsigsclass.FindFuncSigsAndComment(0x0, 0x3fff);
		msg("*** ME761Astra 2nd pass\n");
		functionsigsclass.FindFuncSigsAndComment(0x4000, 0x7fff);
		msg("*** ME761Astra 3rd pass\n");
		functionsigsclass.FindFuncSigsAndComment(0x8000, 0xdfff);
		msg("*** ME761Astra 4th pass\n");
		functionsigsclass.FindFuncSigsAndComment(0x10000, 0xdffff);
	}
	else
	{
		msg("Everything Else\n");
		functionsigsclass.FindFuncSigsAndComment(0x0, 0xffffff);
	}

//	FindFuncSigsAndComment(0x8de4b4, 0x8de566);
}

//Looks for instructions that will probably contain an offset. When found it creates them.
void BoschHelper::SearchForArrayOffsetsAndThenCreate(string sECU)
{
	if(sECU == "bNewME711")
	{
		FindAndCreateArrayOffsets(0x0, 0xffffff);
	}
	else if (sECU == "ME761Astra")
	{
		FindAndCreateArrayOffsets(0x0, 0x3fff);
		FindAndCreateArrayOffsets(0x4000, 0x7fff);
		FindAndCreateArrayOffsets(0x8000, 0xdfff);
		FindAndCreateArrayOffsets(0x10000, 0xdffff);
	}
	else
	{
		FindAndCreateArrayOffsets(0x0, 0x8fffff);
	}
//	FindAndCreateImplicitOffsets(0x8694b4, 0x8694ce);
}
