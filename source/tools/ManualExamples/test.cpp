/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//
// This tool counts the number of times a routine is executed and
// the number of instructions executed in a routine
//

#include "pin.H"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ofstream;
using std::setw;
using std::string;

// This function is called before every instruction is executed
VOID getparam(CHAR *name, CHAR *ps) {
  std::cout << name << ": " << ps << std::endl;
}

const char *StripPath(const char *path) {
  const char *file = strrchr(path, '/');
  if (file)
    return file + 1;
  else
    return path;
}

VOID Routine(RTN rtn, VOID *v) {
  // Allocate a counter for this routine
  string name=RTN_Name(rtn);
  RTN_Open(rtn);
  // Insert a call at the entry point of a routine to increment the call count
  if (name == "PHP_MD5Update")
       RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getparam, IARG_ADDRINT,
                   name.c_str(), IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_END);
 
  RTN_Close(rtn);
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID *v) {
 }

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
  PIN_InitSymbols();

  // Initialize pin
  if (PIN_Init(argc, argv))
    return Usage();

  // Register Routine to be called to instrument rtn
  RTN_AddInstrumentFunction(Routine, 0);

  // Register Fini to be called when the application exits
  PIN_AddFiniFunction(Fini, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}
