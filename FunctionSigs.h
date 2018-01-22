// FunctionSigs.h: interface for the FunctionSigs class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_FUNCTIONSIGS_H__C6DB9FEB_257B_46A5_A944_3629C2B0D33C__INCLUDED_)
#define AFX_FUNCTIONSIGS_H__C6DB9FEB_257B_46A5_A944_3629C2B0D33C__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class FunctionSigs  
{
public:
	FunctionSigs();
	virtual ~FunctionSigs();

private:
public:
	ea_t FindBinaryWithDontCare(uchar* ubinstr, unsigned __int32 nSLength, ea_t eaStartAddress, ea_t eaEndAddr);//Finds the given binary string in the given binary. If 0xff then this is don't care
	ea_t CreateFunctionAndComment(ea_t eaAddr, unsigned char* pFuncName, unsigned char* pComment, unsigned int iTries);// Creates a function at the address and auto comments it
	void Comment(ea_t eaAddr, unsigned char* pDataName, unsigned char* pComment, unsigned int iTries);//Comments the address given
public:
	void FindFuncSigsAndComment(ea_t eaStartAddr, ea_t eaEndAddr);//Looks for specific binary patterns and then makes a subroutine and comments it

};

#endif // !defined(AFX_FUNCTIONSIGS_H__C6DB9FEB_257B_46A5_A944_3629C2B0D33C__INCLUDED_)
