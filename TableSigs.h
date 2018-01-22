// TableSigs.h: interface for the TableSigs class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_TableSIGS_H__C6DB9FEB_257B_46A5_A944_3629C2BFD33C__INCLUDED_)
#define AFX_TableSIGS_H__C6DB9FEB_257B_46A5_A944_3629C2BFD33C__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class TableSigs  
{
public:
	TableSigs();
	virtual ~TableSigs();

private:

public:
	ea_t FindBinaryWithDontCare(uchar* ubinstr, unsigned __int32 nSLength, ea_t eaStartAddress, ea_t eaEndAddr);//Finds the given binary string in the given binary. If 0xff then this is don't care

public:
	void FindTablesAndComment(ea_t eaStartAddr, ea_t eaEndAddr);//Looks for specific binary patterns and then makes a subroutine and comments it

};

#endif // !defined(AFX_TableSIGS_H__C6DB9FEB_257B_46A5_A944_3629C2BFD33C__INCLUDED_)
