/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//
// This tool counts the number of times a routine is executed and
// the number of instructions executed in a routine
//

#include "pin.H"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <list>
#include <ostream>
#include <string>
#include <sys/types.h>
#include <types.h>
#include <unistd.h>
#include <vector>

using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ofstream;
using std::setw;
using std::string;
using std::vector;

vector<string> f_source;
vector<string> f_sp;
vector<string> f_leak;

std::list<UINT64> addressTainted;
std::list<REG> regsTainted;

void init() {
  string fsource[] = {"recv", "WSARecv", "recvfrom", "apr_socket_recv", "read"};
  string fsp[] = {"PHP_MD5Update"};
  string fleak[] = {"send", "sendto", "apr_socket_sendv", "write"};
  f_source =
      vector<string>(fsource, fsource + sizeof(fsource) / sizeof(fsource[0]));
  f_sp = vector<string>(fsp, fsp + sizeof(fsp) / sizeof(fsp[0]));
  f_leak = vector<string>(fleak, fleak + sizeof(fleak) / sizeof(fleak[0]));
}

bool checkAlreadyRegTainted(REG reg) {
  std::list<REG>::iterator i;

  for (i = regsTainted.begin(); i != regsTainted.end(); i++) {
    if (*i == reg) {
      return true;
    }
  }
  return false;
}

VOID removeMemTainted(UINT64 addr) {
  addressTainted.remove(addr);
  std::cout << std::hex << "\t" << addr << " is now freed" << std::endl;
}

VOID addMemTainted(UINT64 addr) {
  addressTainted.push_back(addr);
  std::cout << std::hex << "\t" << addr << " is now tainted" << std::endl;
}

bool taintReg(REG reg) {
  if (checkAlreadyRegTainted(reg) == true) {
    std::cout << "\t" << REG_StringShort(reg) << " is already tainted"
              << std::endl;
    return false;
  }

  switch (reg) {

  case REG_RAX:
    regsTainted.push_front(REG_RAX);
  case REG_EAX:
    regsTainted.push_front(REG_EAX);
  case REG_AX:
    regsTainted.push_front(REG_AX);
  case REG_AH:
    regsTainted.push_front(REG_AH);
  case REG_AL:
    regsTainted.push_front(REG_AL);
    break;

  case REG_RBX:
    regsTainted.push_front(REG_RBX);
  case REG_EBX:
    regsTainted.push_front(REG_EBX);
  case REG_BX:
    regsTainted.push_front(REG_BX);
  case REG_BH:
    regsTainted.push_front(REG_BH);
  case REG_BL:
    regsTainted.push_front(REG_BL);
    break;

  case REG_RCX:
    regsTainted.push_front(REG_RCX);
  case REG_ECX:
    regsTainted.push_front(REG_ECX);
  case REG_CX:
    regsTainted.push_front(REG_CX);
  case REG_CH:
    regsTainted.push_front(REG_CH);
  case REG_CL:
    regsTainted.push_front(REG_CL);
    break;

  case REG_RDX:
    regsTainted.push_front(REG_RDX);
  case REG_EDX:
    regsTainted.push_front(REG_EDX);
  case REG_DX:
    regsTainted.push_front(REG_DX);
  case REG_DH:
    regsTainted.push_front(REG_DH);
  case REG_DL:
    regsTainted.push_front(REG_DL);
    break;

  case REG_RDI:
    regsTainted.push_front(REG_RDI);
  case REG_EDI:
    regsTainted.push_front(REG_EDI);
  case REG_DI:
    regsTainted.push_front(REG_DI);
  case REG_DIL:
    regsTainted.push_front(REG_DIL);
    break;

  case REG_RSI:
    regsTainted.push_front(REG_RSI);
  case REG_ESI:
    regsTainted.push_front(REG_ESI);
  case REG_SI:
    regsTainted.push_front(REG_SI);
  case REG_SIL:
    regsTainted.push_front(REG_SIL);
    break;

  default:
    std::cout << "\t" << REG_StringShort(reg) << " can't be tainted"
              << std::endl;
    return false;
  }
  std::cout << "\t" << REG_StringShort(reg) << " is now tainted" << std::endl;
  return true;
}

bool removeRegTainted(REG reg) {
  switch (reg) {

  case REG_RAX:
    regsTainted.remove(REG_RAX);
  case REG_EAX:
    regsTainted.remove(REG_EAX);
  case REG_AX:
    regsTainted.remove(REG_AX);
  case REG_AH:
    regsTainted.remove(REG_AH);
  case REG_AL:
    regsTainted.remove(REG_AL);
    break;

  case REG_RBX:
    regsTainted.remove(REG_RBX);
  case REG_EBX:
    regsTainted.remove(REG_EBX);
  case REG_BX:
    regsTainted.remove(REG_BX);
  case REG_BH:
    regsTainted.remove(REG_BH);
  case REG_BL:
    regsTainted.remove(REG_BL);
    break;

  case REG_RCX:
    regsTainted.remove(REG_RCX);
  case REG_ECX:
    regsTainted.remove(REG_ECX);
  case REG_CX:
    regsTainted.remove(REG_CX);
  case REG_CH:
    regsTainted.remove(REG_CH);
  case REG_CL:
    regsTainted.remove(REG_CL);
    break;

  case REG_RDX:
    regsTainted.remove(REG_RDX);
  case REG_EDX:
    regsTainted.remove(REG_EDX);
  case REG_DX:
    regsTainted.remove(REG_DX);
  case REG_DH:
    regsTainted.remove(REG_DH);
  case REG_DL:
    regsTainted.remove(REG_DL);
    break;

  case REG_RDI:
    regsTainted.remove(REG_RDI);
  case REG_EDI:
    regsTainted.remove(REG_EDI);
  case REG_DI:
    regsTainted.remove(REG_DI);
  case REG_DIL:
    regsTainted.remove(REG_DIL);
    break;

  case REG_RSI:
    regsTainted.remove(REG_RSI);
  case REG_ESI:
    regsTainted.remove(REG_ESI);
  case REG_SI:
    regsTainted.remove(REG_SI);
  case REG_SIL:
    regsTainted.remove(REG_SIL);
    break;

  default:
    return false;
  }
  std::cout << "\t" << REG_StringShort(reg) << " is now freed" << std::endl;
  return true;
}

VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r,
             UINT64 memOp) {
  std::list<UINT64>::iterator i;
  UINT64 addr = memOp;

  if (opCount != 2)
    return;

  for (i = addressTainted.begin(); i != addressTainted.end(); i++) {
    if (addr == *i) {
      std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": "
                << insDis << std::endl;
      taintReg(reg_r);
      return;
    }
  }
  /* if mem != tained and reg == taint => free the reg */
  if (checkAlreadyRegTainted(reg_r)) {
    std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": "
              << insDis << std::endl;
    removeRegTainted(reg_r);
  }
}

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r,
              UINT64 memOp) {
  std::list<UINT64>::iterator i;
  UINT64 addr = memOp;

  if (opCount != 2)
    return;

  for (i = addressTainted.begin(); i != addressTainted.end(); i++) {
    if (addr == *i) {
      std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": "
                << insDis << std::endl;
      if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
        removeMemTainted(addr);
      return;
    }
  }
  if (checkAlreadyRegTainted(reg_r)) {
    std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": "
              << insDis << std::endl;
    addMemTainted(addr);
  }
}

VOID spreadRegTaint(UINT64 insAddr, std::string insDis, UINT32 opCount,
                    REG reg_r, REG reg_w) {
  if (opCount != 2)
    return;

  if (REG_valid(reg_w)) {
    if (checkAlreadyRegTainted(reg_w) &&
        (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))) {
      std::cout << "[SPREAD]\t" << insAddr << ": " << insDis << std::endl;
      std::cout << "\toutput: " << REG_StringShort(reg_w) << " | input: "
                << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant")
                << std::endl;
      removeRegTainted(reg_w);
    } else if (!checkAlreadyRegTainted(reg_w) &&
               checkAlreadyRegTainted(reg_r)) {
      std::cout << "[SPREAD]\t" << insAddr << ": " << insDis << std::endl;
      std::cout << "\toutput: " << REG_StringShort(reg_w)
                << " | input: " << REG_StringShort(reg_r) << std::endl;
      taintReg(reg_w);
    }
  }
}

VOID Instruction(INS ins, VOID *v) {
  if (INS_OperandCount(ins) > 1 && INS_IsMemoryRead(ins) &&
      INS_OperandIsMemory(ins, 1) && INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ReadMem, IARG_ADDRINT,
                   INS_Address(ins), IARG_PTR, new string(INS_Disassemble(ins)),
                   IARG_UINT32, INS_OperandCount(ins), IARG_UINT32,
                   INS_OperandReg(ins, 0), IARG_MEMORYOP_EA, 0, IARG_END);
  } else if (INS_OperandCount(ins) > 1 && INS_IsMemoryWrite(ins)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteMem, IARG_ADDRINT,
                   INS_Address(ins), IARG_PTR, new string(INS_Disassemble(ins)),
                   IARG_UINT32, INS_OperandCount(ins), IARG_UINT32,
                   INS_OperandReg(ins, 1), IARG_MEMORYOP_EA, 0, IARG_END);
  } else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint, IARG_ADDRINT,
                   INS_Address(ins), IARG_PTR, new string(INS_Disassemble(ins)),
                   IARG_UINT32, INS_OperandCount(ins), IARG_UINT32,
                   INS_RegR(ins, 0), IARG_UINT32, INS_RegW(ins, 0), IARG_END);
  }
}

// This function is called before every instruction is executed
VOID getParam(std::vector<string>::iterator name, UINT64 *ps0, UINT64 ps1) {
  std::cout << *name << ": param1 => " << ps0 << " , param2 => " << ps1
            << std::endl;
  for (std::list<UINT64>::iterator it = addressTainted.begin();
       it != addressTainted.end(); it++) {
    if ((UINT64)ps0 < *it && (UINT64)(ps0) + ps1 > *it) {
      std::cout << "Leaked information from address " << *it << std::endl;
    }
  }
}

VOID getMd5Source(std::vector<string>::iterator name, CHAR *ps, size_t size) {
  std::cout << *name << std::hex << ": ( 0x" << (UINT64)ps << ") " << ps
            << " with size " << size << std::endl;
  for (size_t i = 0; i < size; i++)
    addressTainted.push_back((UINT64)(ps + i));
  std::cout << "[TAINT]\tbytes tainted from " << std::hex << "0x" << (UINT64)ps
            << " to 0x" << (UINT64)(ps + size) << " (via " << *name << ")"
            << std::endl;
}

VOID getSendV(std::vector<string>::iterator name, UINT64 *ps) {
  iovec *p = (iovec *)ps;
  std::cout << *name << ": Base => " << p->iov_base << ", Len => 0x"
            << p->iov_len << std::endl;
  for (std::list<UINT64>::iterator it = addressTainted.begin();
       it != addressTainted.end(); it++) {
    if ((UINT64)p->iov_base < *it && (UINT64)(p->iov_base) + p->iov_len > *it) {
      std::cout << "Leaked information from address " << *it << std::endl;
    }
  }
}
VOID getRecv(std::vector<string>::iterator name, UINT64 *ps0, UINT64 *ps1) {
  std::cout << *name << ": param1 => " << *ps0 << " , param2 => " << *ps1
            << std::endl;
  for (std::list<UINT64>::iterator it = addressTainted.begin();
       it != addressTainted.end(); it++) {
    if ((UINT64)ps0 < *it && (UINT64)(ps0) + *ps1 > *it) {
      std::cout << "Leaked information from address " << *it << std::endl;
    }
  }
}

bool in(string s, vector<string> array) {
  std::vector<string>::iterator pos = std::find(array.begin(), array.end(), s);
  if (pos == array.end())
    return false;
  else
    return true;
}

VOID Routine(RTN rtn, VOID *v) {
  // Allocate a counter for this routine
  string name = RTN_Name(rtn);
  RTN_Open(rtn);
  // std::cout << name << std::endl;
  // Insert a call at the entry point of a routine to increment the call count
  if (in(name, f_sp) /*|| in(name, f_sp) || in(name, f_leak)*/) {
    // std::cout <<"Name: " << name.c_str() << std::endl;version
    std::vector<string>::iterator pos =
        std::find(f_sp.begin(), f_sp.end(), name);
    if (name == "PHP_MD5Update") {
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getMd5Source, IARG_ADDRINT,
                     pos, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
    } else {
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getParam, IARG_ADDRINT, pos,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    }
  }
  if (in(name, f_leak) /*|| in(name, f_sp) || in(name, f_leak)*/) {
    // std::cout <<"Name: " << name.c_str() << std::endl;version
    std::vector<string>::iterator pos =
        std::find(f_leak.begin(), f_leak.end(), name);
    if (name == "apr_socket_sendv" || name == "writev") {
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getSendV, IARG_ADDRINT, pos,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    } else {
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getParam, IARG_ADDRINT, pos,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
    }
  }
  if (in(name, f_source) /*|| in(name, f_sp) || in(name, f_leak)*/) {
    // std::cout <<"Name: " << name.c_str() << std::endl;version
    std::vector<string>::iterator pos =
        std::find(f_source.begin(), f_source.end(), name);
    if (name == "apr_socket_recv") {
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getRecv, IARG_ADDRINT, pos,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
    } else {
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getParam, IARG_ADDRINT, pos,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
    }
  }

  // if (name == "PHP_MD5Final") {
  //   // std::cout <<"Name: " << name.c_str() << std::endl;version
  //   // std::vector<string>::iterator pos =
  //   //     std::find(f_source.begin(), f_source.end(), name);
  //   // std::cout << *pos << std::endl;
  //   RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getparam, IARG_ADDRINT,
  //                  n, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
  // }
  RTN_Close(rtn);
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID *v) {}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage() {
  cerr << "This Pintool counts the number of times a routine is executed"
       << endl;
  cerr << "and the number of instructions executed in a routine" << endl;
  cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
  return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {
  // Initialize symbol table code, needed for rtn instrumentation
  init();

  PIN_InitSymbols();

  // Initialize pin
  if (PIN_Init(argc, argv))
    return Usage();
  PIN_SetSyntaxIntel();

  RTN_AddInstrumentFunction(Routine, 0);
  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();

  return 0;
}
