## Original https://gist.githubusercontent.com/ChoiSG/d61fc7e3fc761499928791714ffbd3e3/raw/13cb12e83dfca590c504d53bf00282321d7a387a/dinvokeSyscall.cs

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
.\encryptor.exe .\calc.bin shellcode.enc --key-hex 0835E04609BDF51A3D385344F541E3505432CBECC0A94395DFB341E45BE5B224 --iv-hex EFF35696B85A572B1074CEA2963D4395 --cs-out calc.cs

```

```bash
Loader.exe [--pid <processId>] [--file <path-to-enc-file>]
(no --pid  -> injects into the first "notepad" process)
(no --file -> downloads from ShellcodeUrl)
```
