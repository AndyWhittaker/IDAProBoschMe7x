// IDAMemCopyPaste.h: interface for the IDAMemCopyPaste class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_IDAMemCopyPaste_H__C6DB9FEB_257B_46A5_A944_3629C2B0D33C__INCLUDED_)
#define AFX_IDAMemCopyPaste_H__C6DB9FEB_257B_46A5_A944_3629C2B0D33C__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class IDAMemCopyPaste  
{
public:
	IDAMemCopyPaste();
	virtual ~IDAMemCopyPaste();

private:
	void copy_buffer(ea_t eaStartAddr, ea_t eaEndAddr);
	void paste_buffer(ea_t eaStartAddr, ea_t eaEndAddr);

public:

public:
	void FindFuncSigsAndComment(void);//Looks for specific binary patterns and then makes a subroutine and comments it

};

#endif // !defined(AFX_IDAMemCopyPaste_H__C6DB9FEB_257B_46A5_A944_3629C2B0D33C__INCLUDED_)
