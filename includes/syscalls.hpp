#pragma once

//  Code below is adapted from @modexpblog. Read linked article for more details.
//  https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#include <windows.h>

struct PS_ATTRIBUTE {
  ULONG Attribute;
  SIZE_T Size;

  union {
    ULONG Value;
    PVOID ValuePtr;
  } u1;

  PSIZE_T ReturnLength;
};

using PPS_ATTRIBUTE = PS_ATTRIBUTE*;

struct UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
};

using PUNICODE_STRING = UNICODE_STRING*;

typedef struct OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
};

using POBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES*;

typedef struct PS_ATTRIBUTE_LIST {
  SIZE_T TotalLength;
  PS_ATTRIBUTE Attributes[1];
};

using PPS_ATTRIBUTE_LIST = PS_ATTRIBUTE_LIST*;

EXTERN_C NTSTATUS NtAllocateVirtualMemory(IN HANDLE ProcessHandle,
                                          IN OUT PVOID* BaseAddress,
                                          IN ULONG ZeroBits,
                                          IN OUT PSIZE_T RegionSize,
                                          IN ULONG AllocationType,
                                          IN ULONG Protect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(IN HANDLE ProcessHandle,
                                       IN PVOID BaseAddress,
                                       IN PVOID Buffer,
                                       IN SIZE_T NumberOfBytesToWrite,
                                       OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtCreateThreadEx(OUT PHANDLE ThreadHandle,
                                   IN ACCESS_MASK DesiredAccess,
                                   IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
                                   IN HANDLE ProcessHandle,
                                   IN PVOID StartRoutine,
                                   IN PVOID Argument OPTIONAL,
                                   IN ULONG CreateFlags,
                                   IN SIZE_T ZeroBits,
                                   IN SIZE_T StackSize,
                                   IN SIZE_T MaximumStackSize,
                                   IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtWaitForSingleObject(IN HANDLE ObjectHandle,
                                        IN BOOLEAN Alertable,
                                        IN PLARGE_INTEGER TimeOut OPTIONAL);

EXTERN_C NTSTATUS NtClose(IN HANDLE Handle);
