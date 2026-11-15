/*
  Small, readable starter rules for Windows executables.
  They look for behaviour hints inside the file body. API-import and packer
  checks are done separately in pe_analyzer.py so nothing is counted twice.
  Add your own rules here, or drop in rules from a community repository.
  Each rule needs `description` and `severity` (high | medium | low) in meta.
*/

rule PowerShell_Download_Cradle
{
    meta:
        description = "References PowerShell together with download or encoded-command strings"
        severity = "high"
    strings:
        $ps  = "powershell" nocase ascii wide
        $dl1 = "DownloadString" ascii wide
        $dl2 = "DownloadFile" ascii wide
        $dl3 = "-EncodedCommand" nocase ascii wide
        $dl4 = "FromBase64String" ascii wide
    condition:
        uint16(0) == 0x5A4D and $ps and any of ($dl*)
}

rule Ransom_Note_Phrases
{
    meta:
        description = "Contains phrases typical of ransomware notes"
        severity = "high"
    strings:
        $r1 = "your files have been encrypted" nocase ascii wide
        $r2 = "bitcoin" nocase ascii wide
        $r3 = "decrypt" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and $r1 and 1 of ($r2, $r3)
}

rule Shadow_Copy_Deletion
{
    meta:
        description = "Contains a command that deletes Windows shadow copies (backup removal)"
        severity = "high"
    strings:
        $v1 = "vssadmin" nocase ascii wide
        $v2 = "delete shadows" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Embedded_Executable
{
    meta:
        description = "Contains a second executable image inside the file (possible dropper)"
        severity = "medium"
    strings:
        $dos = "This program cannot be run in DOS mode" ascii
    condition:
        uint16(0) == 0x5A4D and #dos >= 2
}

rule Persistence_Run_Key
{
    meta:
        description = "References the Windows Run registry key (common for persistence, also used by installers)"
        severity = "low"
    strings:
        $run = "CurrentVersion\\Run" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and $run
}
