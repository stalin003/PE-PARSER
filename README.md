# PE-PARSER
A basic PE parser 

* Currently it is able to parse only 64 bit PE.
* .Net binary are not supported
* Shows all information about the PE


<code>
  
  Example: 
  
  C:\PE_Parser.exe "C:\Users\blesa\source\repos\PE-PARSER\x64\Release\PE_Parser.exe"
  
  DOS HEADER
  ---------------

  e_magic        : 5A4D
  e_clp          : 90
  e_cp           : 3
  e_crlc         : 0
  e_cparhdr      : 4
  e_minalloc     : 0
  e_maxalloc     : FFFF
  e_ss           : 0
  e_sp           : B8
  e_csum         : 0
  e_ip           : 0
  e_cs           : 0
  e_lfarlc       : 40
  e_ovno         : 0
  e_res          :
                   0
                   0
                   0
                   0
  e_oemid        : 0
  e_oeminfo      : 0
  e_res2         :
                   0
                   0
                   0
                   0
                   0
                   0
                   0
                   0
                   0
                   0
  e_lfanew       : F8



  RICH HEADER
  ---------------

  Dans ID                  : 536E6144
  Checksummed padding      : 0
  Checksummed padding      : 0
  Checksummed padding      : 0
  Comp ID                  : A00937809
  Comp ID                  : 201017CBF
  Comp ID                  : 1301057CBF
  Comp ID                  : A01047CBF
  Comp ID                  : 301037CBF
  Comp ID                  : 301016B14
  Comp ID                  : 3A00010000
  Comp ID                  : 101087DD8
  Comp ID                  : 100FF7DD8
  Comp ID                  : 101027DD8



  NT HEADER
  ---------------

  Signature                : 4550


  [*] FILE HEADER:

  Machine                  : 8664
  Number Of Sections       : 6
  Time Date Stamp          : 646B562A
  Pointer To Symbol Table  : 0
  Number Of Symbols        : 0
  Size Of Optional Header  : F0
  Characteristics          : 22


  [*] OPTIONAL HEADER:

  Magic                    : 20B
  MajorLinkerVersion       : E
  MinorLinkerVersion       : 23
  SizeOfCode               : 2A00
  SizeOfInitializedData    : 2E00
  SizeOfUninitializedData  : 0
  AddressOfEntryPoint      : 2D60
  BaseOfCode               : 1000
  ImageBase                : 40000000
  SectionAlignment         : 1000
  FileAlignment            : 200
  MajorOperatingSystemVersion: 6
  MinorOperatingSystemVersion: 0
  MajorImageVersion        : 0
  MinorImageVersion        : 0
  MajorSubsystemVersion    : 6
  MinorSubsystemVersion    : 0
  Win32VersionValue        : 0
  SizeOfImage              : A000
  SizeOfHeaders            : 400
  CheckSum                 : 0
  Subsystem                : 3
  DllCharacteristics       : 8160
  SizeOfStackReserve       : 100000
  SizeOfStackCommit        : 1000
  SizeOfHeapReserve        : 100000
  SizeOfHeapCommit         : 1000
  LoaderFlags              : 0
  NumberOfRvaAndSizes      : 10


  [*] DATA DIRECTORIES:

  Export Directory          rva: 0                         size: 0
  Import Directory          rva: 554C                      size: A0
  Resource Directory        rva: 8000                      size: 1E0
  Exception Directory       rva: 7000                      size: 24C
  Security Directory        rva: 0                         size: 0
  Relocation Directory      rva: 9000                      size: 30
  Debug Directory           rva: 4EE0                      size: 70
  Architecture Directory    rva: 0                         size: 0
  Global Pointer Directory  rva: 0                         size: 0
  TLS Directory             rva: 0                         size: 0
  Configuration Directory   rva: 4DA0                      size: 140
  Bound Import Directory    rva: 0                         size: 0
  IAT Directory             rva: 4000                      size: 1E0
  Delay Import Directory    rva: 0                         size: 0
  .Net MetaData Directory   rva: 0                         size: 0



  SECTION HEADER
  ---------------

  Name            VirtualSize     VirtualAddress  SizeOfRawData   PointerToRawData PointerToRelocations PointerToLinenumbers NumberOfRelocations NumberOfLinenumbers Characteristics
  .text             284C               1000               2A00               400                0                  0                  0                  0                  60000020
  .rdata            1CB0               4000               1E00               2E00               0                  0                  0                  0                  40000040
  .data             6A8                6000               200                4C00               0                  0                  0                  0                  C0000040
  .pdata            24C                7000               400                4E00               0                  0                  0                  0                  40000040
  .rsrc             1E0                8000               200                5200               0                  0                  0                  0                  40000040
  .reloc            30                 9000               200                5400               0                  0                  0                  0                  42000040



  IMAGE IMPORT DISCRIPTOR
  ------------------------

  OrginalFirstThunk (ILT RVA): 55F0
  |----> IMPORT LOOKUP TABLE (struct _IMAGE_THUNK_DATA) <----|
  |----> ITL offset: 43F0
  |----> imageThunkDataCount: 22
  |----> image hint RVA 57D0
  |----> import by name offset: 45D0
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 479
  |--------> function name: ReadFile
  |----> image hint RVA 57DC
  |----> import by name offset: 45DC
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 355
  |--------> function name: HeapFree
  |----> image hint RVA 57E8
  |----> import by name offset: 45E8
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 532
  |--------> function name: SetFilePointer
  |----> image hint RVA 57FA
  |----> import by name offset: 45FA
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: CE
  |--------> function name: CreateFileW
  |----> image hint RVA 5808
  |----> import by name offset: 4608
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 89
  |--------> function name: CloseHandle
  |----> image hint RVA 5816
  |----> import by name offset: 4616
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 351
  |--------> function name: HeapAlloc
  |----> image hint RVA 5822
  |----> import by name offset: 4622
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 2BE
  |--------> function name: GetProcessHeap
  |----> image hint RVA 5B5C
  |----> import by name offset: 495C
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 4DC
  |--------> function name: RtlLookupFunctionEntry
  |----> image hint RVA 5B76
  |----> import by name offset: 4976
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 4E3
  |--------> function name: RtlVirtualUnwind
  |----> image hint RVA 5B8A
  |----> import by name offset: 498A
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 5C0
  |--------> function name: UnhandledExceptionFilter
  |----> image hint RVA 5BA6
  |----> import by name offset: 49A6
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 57F
  |--------> function name: SetUnhandledExceptionFilter
  |----> image hint RVA 5BC4
  |----> import by name offset: 49C4
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 220
  |--------> function name: GetCurrentProcess
  |----> image hint RVA 5BD8
  |----> import by name offset: 49D8
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 59E
  |--------> function name: TerminateProcess
  |----> image hint RVA 5C92
  |----> import by name offset: 4A92
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 281
  |--------> function name: GetModuleHandleW
  |----> image hint RVA 5C7E
  |----> import by name offset: 4A7E
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 385
  |--------> function name: IsDebuggerPresent
  |----> image hint RVA 5C68
  |----> import by name offset: 4A68
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 36F
  |--------> function name: InitializeSListHead
  |----> image hint RVA 5C4E
  |----> import by name offset: 4A4E
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 2F3
  |--------> function name: GetSystemTimeAsFileTime
  |----> image hint RVA 5C38
  |----> import by name offset: 4A38
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 225
  |--------> function name: GetCurrentThreadId
  |----> image hint RVA 5C22
  |----> import by name offset: 4A22
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 221
  |--------> function name: GetCurrentProcessId
  |----> image hint RVA 5C08
  |----> import by name offset: 4A08
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 452
  |--------> function name: QueryPerformanceCounter
  |----> image hint RVA 5BEC
  |----> import by name offset: 49EC
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 38C
  |--------> function name: IsProcessorFeaturePresent
  |----> image hint RVA 5B48
  |----> import by name offset: 4948
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 4D5
  |--------> function name: RtlCaptureContext
  TimeDateStamp: 0
  ForwarderChain: 0
  Name RVA: 5834
  |----> name offset: 4634
  |----> name: KERNEL32.dll
  FirstThunk (IAT RVA): 4000


  OrginalFirstThunk (ILT RVA): 56A8
  |----> IMPORT LOOKUP TABLE (struct _IMAGE_THUNK_DATA) <----|
  |----> ITL offset: 44A8
  |----> imageThunkDataCount: 5
  |----> image hint RVA 5842
  |----> import by name offset: 4642
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 8
  |--------> function name: __C_specific_handler
  |----> image hint RVA 585A
  |----> import by name offset: 465A
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 1B
  |--------> function name: __current_exception
  |----> image hint RVA 5870
  |----> import by name offset: 4670
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 1C
  |--------> function name: __current_exception_context
  |----> image hint RVA 588E
  |----> import by name offset: 468E
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 3E
  |--------> function name: memset
  |----> image hint RVA 5CA6
  |----> import by name offset: 4AA6
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 3C
  |--------> function name: memcpy
  TimeDateStamp: 0
  ForwarderChain: 0
  Name RVA: 5898
  |----> name offset: 4698
  |----> name: VCRUNTIME140.dll
  FirstThunk (IAT RVA): 40B8


  OrginalFirstThunk (ILT RVA): 57A0
  |----> IMPORT LOOKUP TABLE (struct _IMAGE_THUNK_DATA) <----|
  |----> ITL offset: 45A0
  |----> imageThunkDataCount: 5
  |----> image hint RVA 58D6
  |----> import by name offset: 46D6
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 11
  |--------> function name: __stdio_common_vswprintf
  |----> image hint RVA 58BC
  |----> import by name offset: 46BC
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 3
  |--------> function name: __stdio_common_vfprintf
  |----> image hint RVA 58AA
  |----> import by name offset: 46AA
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 0
  |--------> function name: __acrt_iob_func
  |----> image hint RVA 5A42
  |----> import by name offset: 4842
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 1
  |--------> function name: __p__commode
  |----> image hint RVA 59B0
  |----> import by name offset: 47B0
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 54
  |--------> function name: _set_fmode
  TimeDateStamp: 0
  ForwarderChain: 0
  Name RVA: 5AA4
  |----> name offset: 48A4
  |----> name: api-ms-win-crt-stdio-l1-1-0.dll
  FirstThunk (IAT RVA): 41B0


  OrginalFirstThunk (ILT RVA): 5708
  |----> IMPORT LOOKUP TABLE (struct _IMAGE_THUNK_DATA) <----|
  |----> ITL offset: 4508
  |----> imageThunkDataCount: 18
  |----> image hint RVA 5A52
  |----> import by name offset: 4852
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 34
  |--------> function name: _initialize_onexit_table
  |----> image hint RVA 5A6E
  |----> import by name offset: 486E
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 3C
  |--------> function name: _register_onexit_function
  |----> image hint RVA 59CC
  |----> import by name offset: 47CC
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 5
  |--------> function name: __p___argv
  |----> image hint RVA 5A98
  |----> import by name offset: 4898
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 67
  |--------> function name: terminate
  |----> image hint RVA 58F2
  |----> import by name offset: 46F2
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 40
  |--------> function name: _seh_filter_exe
  |----> image hint RVA 5904
  |----> import by name offset: 4704
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 42
  |--------> function name: _set_app_type
  |----> image hint RVA 59E4
  |----> import by name offset: 47E4
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 15
  |--------> function name: _c_exit
  |----> image hint RVA 59DA
  |----> import by name offset: 47DA
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 16
  |--------> function name: _cexit
  |----> image hint RVA 59BE
  |----> import by name offset: 47BE
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 4
  |--------> function name: __p___argc
  |----> image hint RVA 5A8A
  |----> import by name offset: 488A
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 1E
  |--------> function name: _crt_atexit
  |----> image hint RVA 59A8
  |----> import by name offset: 47A8
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 23
  |--------> function name: _exit
  |----> image hint RVA 59A0
  |----> import by name offset: 47A0
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 55
  |--------> function name: exit
  |----> image hint RVA 5992
  |----> import by name offset: 4792
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 37
  |--------> function name: _initterm_e
  |----> image hint RVA 5986
  |----> import by name offset: 4786
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 36
  |--------> function name: _initterm
  |----> image hint RVA 5964
  |----> import by name offset: 4764
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 28
  |--------> function name: _get_initial_narrow_environment
  |----> image hint RVA 5942
  |----> import by name offset: 4742
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 33
  |--------> function name: _initialize_narrow_environment
  |----> image hint RVA 5928
  |----> import by name offset: 4728
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 18
  |--------> function name: _configure_narrow_argv
  |----> image hint RVA 59EE
  |----> import by name offset: 47EE
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 3D
  |--------> function name: _register_thread_local_exe_atexit_callback
  TimeDateStamp: 0
  ForwarderChain: 0
  Name RVA: 5AC4
  |----> name offset: 48C4
  |----> name: api-ms-win-crt-runtime-l1-1-0.dll
  FirstThunk (IAT RVA): 4118


  OrginalFirstThunk (ILT RVA): 56F8
  |----> IMPORT LOOKUP TABLE (struct _IMAGE_THUNK_DATA) <----|
  |----> ITL offset: 44F8
  |----> imageThunkDataCount: 1
  |----> image hint RVA 5914
  |----> import by name offset: 4714
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 9
  |--------> function name: __setusermatherr
  TimeDateStamp: 0
  ForwarderChain: 0
  Name RVA: 5AE6
  |----> name offset: 48E6
  |----> name: api-ms-win-crt-math-l1-1-0.dll
  FirstThunk (IAT RVA): 4108


  OrginalFirstThunk (ILT RVA): 56E8
  |----> IMPORT LOOKUP TABLE (struct _IMAGE_THUNK_DATA) <----|
  |----> ITL offset: 44E8
  |----> imageThunkDataCount: 1
  |----> image hint RVA 5A1C
  |----> import by name offset: 481C
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 8
  |--------> function name: _configthreadlocale
  TimeDateStamp: 0
  ForwarderChain: 0
  Name RVA: 5B06
  |----> name offset: 4906
  |----> name: api-ms-win-crt-locale-l1-1-0.dll
  FirstThunk (IAT RVA): 40F8


  OrginalFirstThunk (ILT RVA): 56D8
  |----> IMPORT LOOKUP TABLE (struct _IMAGE_THUNK_DATA) <----|
  |----> ITL offset: 44D8
  |----> imageThunkDataCount: 1
  |----> image hint RVA 5A32
  |----> import by name offset: 4832
  |
  |--------> HINT (struct _IMPORT_BY_NAME) <----|
  |--------> Hint: 16
  |--------> function name: _set_new_mode
  TimeDateStamp: 0
  ForwarderChain: 0
  Name RVA: 5B28
  |----> name offset: 4928
  |----> name: api-ms-win-crt-heap-l1-1-0.dll
  FirstThunk (IAT RVA): 40E8





  IMAGE BASE RELOCATION
  ------------------------

  reloc directory RVA: 9000
  reloc Directory offset: 5400

  virtual address: 4000
  block size     : 30
  item  : A1E0            offset: 1E0             type  : A
  item  : A1E8            offset: 1E8             type  : A
  item  : A1F0            offset: 1F0             type  : A
  item  : A1F8            offset: 1F8             type  : A
  item  : A200            offset: 200             type  : A
  item  : A210            offset: 210             type  : A
  item  : A220            offset: 220             type  : A
  item  : A238            offset: 238             type  : A
  item  : A240            offset: 240             type  : A
  item  : A270            offset: 270             type  : A
  item  : A278            offset: 278             type  : A
  item  : ADF8            offset: DF8             type  : A
  item  : AE10            offset: E10             type  : A
  item  : AE18            offset: E18             type  : A
  item  : AEA0            offset: EA0             type  : A
  item  : AEB8            offset: EB8             type  : A
  item  : AEC0            offset: EC0             type  : A
  item  : AEC8            offset: EC8             type  : A
  item  : AED0            offset: ED0             type  : A
  item  : AED8            offset: ED8             type  : A
  
</code>
