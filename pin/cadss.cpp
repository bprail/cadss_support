/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This file contains an ISA-portable PIN tool for tracing instructions
 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <map>
#include <unistd.h>
#include <stdio.h>

#include "pin.H"
using std::cerr;
using std::endl;
using std::setw;
using std::string;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "jumpmix.out", "specify profile file name");

KNOB< BOOL > KnobPid(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "append pid to output");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

static INT32 Usage()
{
    cerr << "This pin tool collects a profile of jump/branch/call instructions for an application\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;
    return -1;
}

uint64_t lastPC;
uint8_t lastBranch;
INT32 branchReg;

FILE* fo;

char pendingBranch[256];

/* ===================================================================== */
static std::ofstream* out = 0;
void notBranchIns(uint64_t pcAddress)
{
    if (lastBranch == 1)
    {
        lastBranch = 0;
    //    *out << std::hex << pcAddress << " " << std::dec << branchReg << endl;
        fprintf(fo, "%s %lx %d\n", pendingBranch, pcAddress, branchReg);
    }
}

void branchIns(uint32_t taken, uint64_t pcAddress, INT32 bReg)
{
    notBranchIns(pcAddress);
    
//    *out << "B " << std::hex << pcAddress << " ";
    sprintf(pendingBranch, "B %lx ", pcAddress);
    if (taken == 1)
    {
        lastBranch = 1;
        branchReg = bReg;
    }
    else
    {
        lastBranch = 0;
    //    *out << pcAddress + 4 << " " << std::dec << bReg << endl;
        fprintf(fo, "%s %lx %d\n", pendingBranch, pcAddress + 4, bReg);
    }
}

void ALUINS(UINT32 c, UINT64 addrC, INT32 op0, INT32 op1, INT32 op2)
{
    notBranchIns(addrC);
 //   *out << (char)c << " " << std::hex << addrC << " " << std::dec << op0 << ", " << op1 << ", " << op2 << endl;
    fprintf(fo, "%c %lx %d, %d, %d\n", c, addrC, op0, op1, op2);
}

void MEMINS(UINT32 c, UINT64 iaddr, UINT64 memAddr, UINT32 size, INT32 op0)
{
    notBranchIns(iaddr);
 //   *out << (char)c << " " << std::hex << memAddr << "," << std::dec << size << " " << op0 << endl;
    fprintf(fo, "%c %lx,%d %d\n", c, memAddr, size, op0);
}

INT32 convertReg(REG r)
{
    if (r == REG_INVALID_) return -1;
    if (r <= REG_FIRST) return -1;
    
    r = REG_FullRegName(r);
    
    if (r <= REG_R15) return (r - 3);
    
    if (r == REG_RFLAGS) return 32;
    
    if (r < REG_YMM0) return -1;  // could have XMM?
    
    if (r > REG_YMM31) return -1; // COULD have ZMM?
    
    return (16 + (r - REG_YMM0));
}

INT32 convertOp(INS ins, UINT32 idx, bool *dest, bool *src)
{
    REG r = INS_OperandReg(ins, idx);
    
    *dest = INS_OperandWritten(ins, idx);
    *src = INS_OperandRead(ins, idx);
    
    return convertReg(r);
}

void populateRegSet(INT32 op[], INS ins, UINT32 count)
{
    bool dest = false;
    bool src = false;
    int destIdx = -1;
    int nextIdx = 1;
    INT32 r;
    //INT32 op[3] = {-1, -1, -1};
    op[0] = op[1] = op[2] = -1;
    
    if (count > 0)
    {
        r = convertOp(ins, 0, &dest, &src);
        if (dest == true) 
        {
            destIdx = 0;
            op[0] = r;
        }
        
        if (src == true)
        {
            op[1] = r;
            nextIdx = 2;
        }
        
        if (count > 1)
        {
            r = convertOp(ins, 1, &dest, &src);
            if (dest == true && destIdx == -1) 
            {
                destIdx = 1;
                op[0] = r;
            }
            
            if (src == true)
            {
                op[nextIdx] = r;
                nextIdx++;
            }
            
            if (count > 2)
            {
                r = convertOp(ins, 2, &dest, &src);
               // *out << INS_Disassemble(ins) << "\t";
               // *out << count << "\t" << r << "\t" << INS_OperandReg(ins, 2) << endl;
                if (dest == true)
                {
                    if (destIdx == -1)
                    {
                        destIdx = 2;
                        op[0] = r;
                    }
                    else if (op[2] == -1)
                    {
                        op[2] = r;
                    }
                }
                else if (op[2] == -1)
                {
                    op[2] = r;
                }
            }
        }
    }
    
    if ((op[0] + op[1] + op[2]) == -3)
    {
     //   *out << INS_Disassemble(ins) << endl;
     //
     /*
     mov qword ptr [rbp-0x1e0], 0x0
call qword ptr [rip+0x29f85]
     
     */
     
    }
}

void insertALU(INS ins, UINT64 iaddrC, char c)
{
    UINT32 count = INS_OperandCount(ins);
    INT32 op[3];
    
    populateRegSet(op, ins, count);
    
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ALUINS, IARG_UINT32, (UINT32)c, 
                    IARG_UINT64, iaddrC, IARG_UINT32, op[0], IARG_UINT32, op[1], IARG_UINT32, op[2], IARG_END);
}

VOID Instruction(INS ins, void* v)
{
    const ADDRINT iaddr = INS_Address(ins);
    uint64_t iaddrC = static_cast< UINT64 >(iaddr);
    
    if (INS_IsRet(ins)|| INS_IsSyscall(ins) || INS_IsDirectControlFlow(ins) ||
        INS_IsIndirectControlFlow(ins))
    {
        bool src, dest;
        UINT32 count = INS_OperandCount(ins);
        INT32 r = -1;
        if (count > 0)
        {
            r = convertOp(ins, 0, &dest, &src);
            if (r == -1 && count > 1)
                r = convertOp(ins, 1, &dest, &src);
            if (r == -1 && count > 2)
            {
                r = convertOp(ins, 2, &dest, &src);
            }
        }
        
        if (r == -1) r = 32;
        
        //std::cout << iaddrC << " " << INS_Disassemble(ins) << endl;
        
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)branchIns, IARG_BRANCH_TAKEN, IARG_UINT64, iaddrC, IARG_UINT32, r, IARG_END);
        return;
    }
    
    for (UINT32 opIdx = 0; opIdx < INS_MemoryOperandCount(ins); opIdx++)
    {
        const ADDRINT iaddr = INS_Address(ins);
        UINT32 readSize = INS_MemoryOperandSize(ins, opIdx);
        INT32 op[3];
        UINT32 count = INS_OperandCount(ins);
        
        populateRegSet(op, ins, count);
        char optype = '\0';
        INT32 op0 = -1;     
        auto memType = IARG_MEMORYWRITE_EA;
        
        if (INS_MemoryOperandIsRead(ins, opIdx))
        {
            optype = 'L';
            if (op[0] != -1) op0 = op[0];
            else if (op[1] != -1) op0 = op[1];
            else op0 = op[2];
            
            memType = IARG_MEMORYREAD_EA;
        }
            
        if (INS_MemoryOperandIsWritten(ins, opIdx))
        {
            optype = 'S';
            if (op[1] != -1) op0 = op[1];
            else if (op[2] != -1) op0 = op[2];
            else op0 = op[0];
        }
        
        if (optype == '\0') continue;
        
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) MEMINS, IARG_UINT32, (UINT32) optype,
                       IARG_UINT64, iaddr, memType, IARG_UINT32, readSize, IARG_UINT32, op0, IARG_END);
    }
    
    auto opC = INS_Opcode(ins);
    auto opT = INS_Category(ins);
    switch (opT)
    {
        case XED_CATEGORY_BINARY:
            switch (opC)
            {
                case XED_ICLASS_MUL:
                case XED_ICLASS_IMUL:
                case XED_ICLASS_DIV:
                case XED_ICLASS_IDIV:
                    insertALU(ins, iaddrC, 'X');
                    break;
                    
                default:
                    insertALU(ins, iaddrC, 'A');
                    break;
                
            }
            break;
        
        case XED_CATEGORY_SSE:
            insertALU(ins, iaddrC, 'X');
            break;
        
        case XED_CATEGORY_PUSH:
        case XED_CATEGORY_POP:
        case XED_CATEGORY_NOP:
        case XED_CATEGORY_WIDENOP:
            // skip these ops
            break;
            
        default:
            insertALU(ins, iaddrC, 'A');
            break;
    }
    
    // REG_FullRegName(REG) -> returns full register for arch  AL-> RAX, etc
    // 3 - rdi, 4 - rsi, 5 - rbp, 6 - rsp, 7 - rbx, 8 - rdx, 9 - rcx, a - rax, b - r8
    // c - r9, d - r10, e - r11, f - r12, 10 - r13, 11 - r14, 12 - r15, 19 - rflags
    // ymm0 (7b)   REG_YMM0 = REG_YMM_BASE,
    
    /*
      MUL / IMUL / DIV is BINARY
      stuff is SSE
      LEA is MISC
      MOV is DATAXFER
      XOR is LOGICAL
      TEST is LOGICAL
      CMP is BINARY
      SETNZ is SETCC
      BT, BSF is BITBYTE ???
      CDQE is CONVERT
      NOP is WIDENOP or NOP
      ROL is ROTATE
      CMOVNZ is CMOV 
      
    */
    
    /*
    INT32 count            = INS_OperandCount(ins);
    INS_OperandReg	(	INS 	ins,
UINT32 	n 
)	
INT32 INS_Category	(	const INS 	ins	)	
The full mapping of opcodes to categories can be found in the idata.txt file in 
the Intel(R) X86 Encoder Decoder distribution (which is distributed as part of the 
Pin kit). The category enumeration can be found in the file "xed-category-enum.h".

OPCODE INS_Opcode	(	INS 	ins	)	

    for (UINT32 opIdx = 0; opIdx < INS_MemoryOperandCount(ins); opIdx++)
    {
        const ADDRINT iaddr = INS_Address(ins);
        UINT32 readSize = INS_MemoryOperandSize(ins, opIdx);
        if (INS_MemoryOperandIsRead(ins, opIdx))
            
        if (INS_MemoryOperandIsWritten(ins, opIdx))
    }
*/
}

/* ===================================================================== */

VOID Fini(int n, void* v)
{
    
    out->close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    string filename = KnobOutputFile.Value();
    if (KnobPid)
    {
        filename += "." + decstr(getpid());
    }
    out = new std::ofstream(filename.c_str());

    fo = fopen(filename.c_str(), "w");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
