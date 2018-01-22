// TableSigs.cpp: implementation of the TableSigs class.
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
#include <lines.hpp>
#include <name.hpp>

#include "TableSigs.h" //Has all the Table signatures stored within it

//////////////////////////////////////////////////////////////////////
// Table Signatures
//////////////////////////////////////////////////////////////////////
#define NUM_DATA_SIGS	3

unsigned char ts_Tablenames[NUM_DATA_SIGS][255] = 
		{
			{"LineariseMAF"},
			{"LineariseEGT"},
			{"LineariseCTS"}
		};

unsigned char ts_Tablecomments[NUM_DATA_SIGS][255] = 
		{
			{"Table to linearise the Hot Wire MAF output"},
			{"Table to linearise the EGT output"},
			{"Table to linearise the CTS output"}
		};
unsigned char ts_sigs[NUM_DATA_SIGS][310] = 
		{
			//Linearise MAF
			{0x93,0x05,0x9B,0x05,0xA2,0x05,0xAA,0x05,0xB2,0x05,0xB9,0x05,0xC1,0x05,0xC8,0x05},
			//Linearise EGT
			{0x12,0x00,0x00,0x00,0x9A,0x19,0x17,0x28,0x39,0x36,0x0B,0x44,0x9D,0x51,0xFA,0x5E},
			//Linearise CTS
			{0x14,0x00,0x00,0x00,0x24,0x00,0x2C,0x00,0x38,0x00,0x44,0x00,0x58,0x00,0x70,0x00}
		};

unsigned int ts_siglen[NUM_DATA_SIGS] = {16, 16, 16};

//////////////////////////////////////////////////////////////////////
//,Construction/Destruction
//////////////////////////////////////////////////////////////////////

TableSigs::TableSigs()
{
}

TableSigs::~TableSigs()
{

}
//////////////////////////////////////////////////////////////////////
// Helpers
//////////////////////////////////////////////////////////////////////

//Finds the given binary string in the given binary. If 0xff then this is don't care
ea_t TableSigs::FindBinaryWithDontCare(uchar* ubinstr,unsigned __int32 nSLength,ea_t eaStartAddress,ea_t eaEndAddr) 
{
	ea_t		eaAddr = BADADDR,eaSearchAddr=0,nIndexA=0,nIndexB=0;
	uchar		nRead=0;
	int			iBit = 0;
	ulong		v=0;

//	ea1stAddr = find_binary(ea_t startea,ea_t endea,ubinstr,16,sflag);
//	msg("FindBinaryWithDontCare()");
	for(nIndexA=eaStartAddress; nIndexA < eaEndAddr;)
	{
		eaAddr = nIndexA;//Store where we are.
		nRead = get_8bit(nIndexA,v,iBit);//Read 8bits but remember that nIndexA is automatically incremented
		if (nIndexA==BADADDR)//Have we ran out of bytes?
		{
			return BADADDR;
		}
		if (nIndexA>= (eaEndAddr-1))
			return BADADDR;

		if(nRead == *ubinstr)
		{// We're matched for the 1st char,now check the rest
//			msg("FindBinaryWithDontCare() found 0x%x at 0x%x with length %lu\n",nRead, nIndexA, nSLength);
			for(nIndexB=1; nIndexB < nSLength; nIndexB++)
			{
				eaSearchAddr= eaAddr + nIndexB;
				if(*(ubinstr+nIndexB) != 0xff) //check for don't care flag
				{
					nRead = get_8bit(eaSearchAddr,v,iBit);
//					msg(":    found 0x%x\n",nRead);
					if (eaSearchAddr==BADADDR)//Have we ran out of bytes?
					{
						eaAddr=BADADDR;
//						msg(" not found, ran beyond binary address space\n");
						return BADADDR;
					}
					if(nRead != *(ubinstr+nIndexB))
					{
//						msg(" no match.\n");
						eaAddr=BADADDR;
						break;// No longer matched,exit this for(..) loop
					}
					else if(nIndexB==(nSLength-1))
					{
//						msg(" binary string matched at 0x%x.\n",eaAddr);
						return eaAddr; // String completely matched
					}
				}
//				else
//					msg(": ignoring 0xff\n");
			}
		}
	}
//	msg("\n");
	return eaAddr;
}


//////////////////////////////////////////////////////////////////////
// Implementation
//////////////////////////////////////////////////////////////////////

//Looks for specific binary patterns and then makes a table and comments it
void TableSigs::FindTablesAndComment(ea_t eaStartAddr, ea_t eaEndAddr)
{
	msg("Finding Table signatures....\n");

	unsigned int	uIndex=0, iTry=0, iTries=0;
	ea_t			eaAddr;
	char			ucBuf[255];

	for(uIndex=0; uIndex < NUM_DATA_SIGS; uIndex++)
	{
		msg("\nSearching for %s, len = %lu\n",ts_Tablenames[uIndex], ts_siglen[uIndex]);
		for(iTry=eaStartAddr, iTries=0; iTry<eaEndAddr; iTry=eaAddr,iTries++)//We may have duplicates
		{
			//Search from the last place until the end of the database
			eaAddr = FindBinaryWithDontCare(ts_sigs[uIndex], ts_siglen[uIndex], iTry, eaEndAddr);
			if (eaAddr != BADADDR)
			{
				qsnprintf(ucBuf, 40, "%s_%x", (char*)ts_Tablenames[uIndex], eaAddr);//Create a unique name
				set_name(eaAddr, ucBuf, SN_PUBLIC);//set the name of the Table

				//We now want to comment the Table
//				func_t* functTable = get_func(eaAddr); // get a pointer to the Table chunk
//				del_func_cmt(functTable,1);//delete the existing comment
//				update_func(functTable);
//				set_func_cmt(functTable,(char*)ts_Tablecomments[uIndex],1);//Make a repeatable comment
//				update_func(functTable);
//				msg("Table finishes at: 0x0%x\n", functTable->endEA);
				//Try the next set of addresses
//				eaAddr=functTable->endEA;// the end of the Table just created.
			}
			else if(iTries==0)
			{
				msg("    Try %d, nothing found\n", iTries);
				eaAddr+=0x1;//TO DO: Find the length of the Table just created.
				break;
			}
			else
			{
				msg("    Try %d, no further Tables found\n", iTries);
				eaAddr+=0x1;//TO DO: Find the length of the Table just created.
				break;
			}
//			eaAddr+=0x10;//TO DO: Find the length of the Table just created.
//			eaAddr=functTable->endEA;
		}
	}
}