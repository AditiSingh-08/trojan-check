"""Constants shared by the PE analyzer and the scoring step (no third-party imports)."""

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# Section names produced by common compilers/linkers (MSVC, MinGW, Delphi, Go...).
STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata",
    ".xdata", ".tls", ".bss", ".crt", ".didat", ".gfids", ".00cfg", ".rodata",
    ".debug", "code", "data", "bss", ".itext", ".sdata",
}

# Section names left behind by well-known packers/protectors.
PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", ".upx0", ".upx1", "upx!", ".aspack", ".adata",
    ".themida", ".vmp0", ".vmp1", ".petite", ".mpress1", ".mpress2",
    ".nsp0", ".nsp1", ".nsp2", ".enigma1", ".enigma2", ".packed",
}

# Windows API names grouped by behaviour. A single hit is rarely meaningful,
# so the scoring step decides how many hits per group are needed.
SUSPICIOUS_APIS = {
    "process_injection": {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
        "NtWriteVirtualMemory", "RtlCreateUserThread",
    },
    "keylogging": {
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyboardState",
    },
    "anti_debugging": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "NtSetInformationThread", "OutputDebugStringA",
    },
    "downloader": {
        "URLDownloadToFileA", "URLDownloadToFileW",
        "URLDownloadToCacheFileA", "URLDownloadToCacheFileW",
    },
}
