rule sus_bytepattern_ntreadvirtualmemory
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtReadVi" wide ascii
        $s2 = "rtualMem" wide ascii
        $s3 = "ory" wide ascii
        $not = "NtReadVirtualMemory" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}


rule sus_bytepattern_ntprotectvirtualmemory
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtProtec" wide ascii
        $s2 = "tVirtual" wide ascii
        $s3 = "ory" wide ascii
        $not = "NtProtectVirtualMemory" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntsuspendthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtSuspen" wide ascii
        $s2 = "dThread" wide ascii
        $not = "NtSuspendThread" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntresumethread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtResume" wide ascii
        $s2 = "Thread" wide ascii
        $not = "NtResumeThread" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntsetcontextthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtSetCon" wide ascii
        $s2 = "textThre" wide ascii
        $s3 = "ad" wide ascii
        $not = "NtSetContextThread" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}


rule sus_bytepattern_ntqueueapcthreadex
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtQueue" wide ascii
        $s2 = "pcThread" wide ascii
        $s3 = "Ex" wide ascii
        $not = "NtQueueApcThreadEx" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntmapviewofsectionex
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtMapVie" wide ascii
        $s2 = "wOfSecti" wide ascii
        $s3 = "onEx" wide ascii
        $not = "NtMapViewOfSectionEx" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntgetcontexthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtGetCon" wide ascii
        $s2 = "textThre" wide ascii
        $not = "NtGetContextThread" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntallocatevirtualmemoryex
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtAlloca" wide ascii
        $s2 = "teVirtua" wide ascii
        $s3 = "lMemoryE" wide ascii
        $not = "NtAllocateVirtualMemoryEx" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntsetinformationprocess
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtSetInf" wide ascii
        $s2 = "ormation" wide ascii
        $s3 = "Process" wide ascii
        $not = "NtSetInformationProcess" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntmapviewofsection
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtMapVie" wide ascii
        $s2 = "wOfSecti" wide ascii
        $s3 = "ion" wide ascii
        $not = "NtMapViewOfSection" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_nzwdeviceiocontrolfile
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "ZwDevice" wide ascii
        $s2 = "IoContro" wide ascii
        $s3 = "lFile" wide ascii
        $not = "ZwDeviceIoControlFile" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntallocatevirtualmemory
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtAlloca" wide ascii
        $s2 = "teVirtua" wide ascii
        $s3 = "lMemory" wide ascii
        $not = "NtAllocateVirtualMemory" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntqueryinformationthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtQueryI" wide ascii
        $s2 = "nformati" wide ascii
        $s3 = "onThread" wide ascii
        $not = "NtQueryInformationThread" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_zwsetinformationthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "ZwSetInf" wide ascii
        $s2 = "ormation" wide ascii
        $s3 = "Thread" wide ascii
        $not = "ZwSetInformationThread" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntqueueapcthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtQueueA" wide ascii
        $s2 = "pcThread" wide ascii
        $not = "NtQueueApcThread" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntunmapviewofsectionex
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "NtUnmapV" wide ascii
        $s2 = "iewOfSec" wide ascii
        $s3 = "tionEx" wide ascii
        $not = "NtUnmapViewofSectionEx" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_showwindow
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "ShowWind" wide ascii
        $s2 = "ow" wide ascii
        $not = "ShowWindow" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_getconsolewindow
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "GetConso" wide ascii
        $s2 = "leWindow" wide ascii
        $not = "GetConsoleWindow" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_getprocaddress
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "GetProcA" wide ascii
        $s2 = "ddress" wide ascii
        $not = "GetProcAddress" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_loadlibrary
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "LoadLibr" wide ascii
        $s2 = "ary" wide ascii
        $not = "LoadLibrary" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_internetopena
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "Internet" wide ascii
        $s2 = "OpenA" wide ascii
        $not = "InternetOpenA" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_internetopenurla
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "Internet" wide ascii
        $s2 = "OpenUrlA" wide ascii
        $not = "InternetOpenUrlA" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_internetreadfile
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "Internet" wide ascii
        $s2 = "ReadFile" wide ascii
        $not = "InternetReadFile" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_internetclosehandle
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "Internet" wide ascii
        $s2 = "CloseHan" wide ascii
        $s3 = "dle" wide ascii
        $not = "InternetCloseHandle" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_createfilea
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "CreateFi" wide ascii
        $s2 = "leA" wide ascii
        $not = "CreateFileA" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_heapalloc
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "HeapAllo" wide ascii
        $not = "HeapAlloc" fullword

    condition:
        $start and not $not and filesize < 1000KB
}

rule sus_bytepattern_writefile
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "WriteFil" wide ascii
        $not = "WriteFile" fullword

    condition:
        $start and $not and filesize < 1000KB
}

rule sus_bytepattern_closehandle
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "CloseHan" wide ascii
        $s2 = "dle" wide ascii
        $not = "CloseHandle" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2  < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_virtualalloc
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "VirtualA" wide ascii
        $s2 = "lloc" wide ascii
        $not = "VirtualAlloc" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_getprocessheap
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "GetProce" wide ascii
        $s2 = "rtuassHeaplMem" wide ascii
        $not = "GetProcessHeap" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_regopenkeyexa
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "RegOpenK" wide ascii
        $s2 = "eyExA" wide ascii
        $not = "RegOpenKeyExA" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_runkeys
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble a run key in Position Independent Code (PIC)."
    strings:
        $start = "SOFTWARE" wide ascii nocase
        $s2 = "\\Microso" wide ascii nocase
        $s3 = "\\ft\\Windo" wide ascii nocase
        $s4 = "ws\\Curre" wide ascii nocase
        $s5 = "ntVersio" wide ascii nocase
        $s6 = "n\\Run" wide ascii nocase
        $not1 = "SOFTWARE\\Microsoft\\CurrentVersion\\Run" fullword
        $not2 = "SOFTWARE\\Microsoft\\CurrentVersion\\RunOnce" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 and @s4 and @s5 and @s6  < (@start[i]+60) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not1 and not $not2 and filesize < 1000KB
}

rule sus_bytepattern_regsetkeyvaluea
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "RegSetKe" wide ascii
        $s2 = "yValueA" wide ascii
        $not = "RegSetKeyValueA" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2  < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_exitprocess
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "ExitProc" wide ascii
        $s2 = "ess" wide ascii
        $not = "ExitProcess" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2  < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB

}

rule sus_bytepattern_createdirectorya
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "CreateDi" wide ascii
        $s2 = "rectoryA" wide ascii
        $not = "CreateDirectoryA" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2  < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB

}

rule sus_bytepattern_expandenvironmentstrings
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "ExpandEn" wide ascii
        $s2 = "vironmen" wide ascii
        $s3 = "tStrings" wide ascii
        $not = "ExpandEnvironmentStrings" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB

}

rule sus_bytepattern_virtualprotect
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC)."
    strings:
        $start = "VirtualP" wide ascii
        $s2 = "rotect" wide ascii
        $not = "VirtualProtect" fullword

    condition:
        uint16(0) == 0x5a4d and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}
