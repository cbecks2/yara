import "pe"

rule sus_bytepattern_ntreadvirtualmemory
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtReadVi" ascii
        $s2 = "rtualMem" ascii
        $s3 = "ory" ascii
        $not = "NtReadVirtualMemory" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}


rule sus_bytepattern_ntprotectvirtualmemory
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtProtec" ascii
        $s2 = "tVirtual" ascii
        $s3 = "ory" ascii
        $not = "NtProtectVirtualMemory" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntsuspendthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtSuspen" ascii
        $s2 = "dThread" ascii
        $not = "NtSuspendThread" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntresumethread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtResume" ascii
        $s2 = "Thread" ascii
        $not = "NtResumeThread" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntsetcontextthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtSetCon" ascii
        $s2 = "textThre" ascii
        $s3 = "ad" ascii
        $not = "NtSetContextThread" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}


rule sus_bytepattern_ntqueueapcthreadex
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtQueue" ascii
        $s2 = "pcThread" ascii
        $s3 = "Ex" ascii
        $not = "NtQueueApcThreadEx" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntmapviewofsectionex
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtMapVie" ascii
        $s2 = "wOfSecti" ascii
        $s3 = "onEx" ascii
        $not = "NtMapViewOfSectionEx" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntgetcontexthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtGetCon" ascii
        $s2 = "textThre" ascii
        $not = "NtGetContextThread" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntallocatevirtualmemoryex
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtAlloca" ascii
        $s2 = "teVirtua" ascii
        $s3 = "lMemoryE" ascii
        $not = "NtAllocateVirtualMemoryEx" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntsetinformationprocess
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtSetInf" ascii
        $s2 = "ormation" ascii
        $s3 = "Process" ascii
        $not = "NtSetInformationProcess" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntmapviewofsection
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtMapVie" ascii
        $s2 = "wOfSecti" ascii
        $s3 = "ion" ascii
        $not = "NtMapViewOfSection" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_nzwdeviceiocontrolfile
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "ZwDevice" ascii
        $s2 = "IoContro" ascii
        $s3 = "lFile" ascii
        $not = "ZwDeviceIoControlFile" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntallocatevirtualmemory
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtAlloca" ascii
        $s2 = "teVirtua" ascii
        $s3 = "lMemory" ascii
        $not = "NtAllocateVirtualMemory" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntqueryinformationthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtQueryI" ascii
        $s2 = "nformati" ascii
        $s3 = "onThread" ascii
        $not = "NtQueryInformationThread" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_zwsetinformationthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "ZwSetInf" ascii
        $s2 = "ormation" ascii
        $s3 = "Thread" ascii
        $not = "ZwSetInformationThread" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntqueueapcthread
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtQueueA" ascii
        $s2 = "pcThread" ascii
        $not = "NtQueueApcThread" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_ntunmapviewofsectionex
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "NtUnmapV" ascii
        $s2 = "iewOfSec" ascii
        $s3 = "tionEx" ascii
        $not = "NtUnmapViewofSectionEx" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_showwindow
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"
        
    strings:
        $start = "ShowWind" ascii
        $s2 = "ow" ascii
        $not = "ShowWindow" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_getconsolewindow
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "GetConso" ascii
        $s2 = "leWindow" ascii
        $not = "GetConsoleWindow" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_getprocaddress
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "GetProcA" ascii
        $s2 = "ddress" ascii
        $not = "GetProcAddress" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_loadlibrary
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "LoadLibr" ascii
        $s2 = "ary" ascii
        $not = "LoadLibrary" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_internetopena
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "Internet" ascii
        $s2 = "OpenA" ascii
        $not = "InternetOpenA" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_internetopenurla
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "Internet" ascii
        $s2 = "OpenUrlA" ascii
        $not = "InternetOpenUrlA" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_internetreadfile
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "Internet" ascii
        $s2 = "ReadFile" ascii
        $not = "InternetReadFile" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_internetclosehandle
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "Internet" ascii
        $s2 = "CloseHan" ascii
        $s3 = "dle" ascii
        $not = "InternetCloseHandle" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}


rule sus_bytepattern_heapalloc
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "HeapAllo" ascii
        $not = "HeapAlloc" ascii wide

    condition:
        $start and not $not and filesize < 1000KB
}


rule sus_bytepattern_closehandle
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "CloseHan" ascii
        $s2 = "dle" ascii
        $not = "CloseHandle" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2  < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_virtualalloc
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "VirtualA" ascii
        $s2 = "lloc" ascii
        $not = "VirtualAlloc" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_getprocessheap
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "GetProce" ascii
        $s2 = "rtuassHeaplMem" ascii
        $not = "GetProcessHeap" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_regopenkeyexa
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "RegOpenK" ascii
        $s2 = "eyExA" ascii
        $not = "RegOpenKeyExA" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_runkeys
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "SOFTWARE" ascii nocase
        $s2 = "\\Microso" ascii nocase
        $s3 = "\\ft\\Windo" ascii nocase
        $s4 = "ws\\Curre" ascii nocase
        $s5 = "ntVersio" ascii nocase
        $s6 = "n\\Run" ascii nocase
        $not1 = "SOFTWARE\\Microsoft\\CurrentVersion\\Run" ascii wide
        $not2 = "SOFTWARE\\Microsoft\\CurrentVersion\\RunOnce" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 and @s4 and @s5 and @s6  < (@start[i]+60) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not1 and not $not2 and filesize < 1000KB
}

rule sus_bytepattern_regsetkeyvaluea
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "RegSetKe" ascii
        $s2 = "yValueA" ascii
        $not = "RegSetKeyValueA" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2  < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule sus_bytepattern_exitprocess
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "ExitProc" ascii
        $s2 = "ess" ascii
        $not = "ExitProcess" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2  < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB

}

rule sus_bytepattern_createdirectorya
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "CreateDi" ascii
        $s2 = "rectoryA" ascii
        $not = "CreateDirectoryA" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2  < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB

}

rule sus_bytepattern_expandenvironmentstrings
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "ExpandEn" ascii
        $s2 = "vironmen" ascii
        $s3 = "tStrings" ascii
        $not = "ExpandEnvironmentStrings" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 and @s3 < (@start[i]+40) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB

}

rule sus_bytepattern_virtualprotect
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    strings:
        $start = "VirtualP" ascii
        $s2 = "rotect" ascii
        $not = "VirtualProtect" ascii wide

    condition:
        uint16(0) == 0x5a4d and pe.number_of_imports < 1 and pe.number_of_signatures < 1 and for all i in (1..#start): ( @s2 < (@start[i]+20) ) // For all matches on $start, make sure the offsets of the remaining patterns are within X bytes.
        and not $not and filesize < 1000KB
}

rule high_count_sus_bytepattern_match
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-03-10"
        desc = "x64 has 8 byte registers. This rule looks for 8 byte string patterns that may resemble suspicious API calls in Position Independent Code (PIC). The filter for no imports exists because KnownDLLs are cached in virtual memory and shared with all processes."
        reference = "https://docs.microsoft.com/en-us/archive/blogs/larryosterman/what-are-known-dlls-anyway"

    condition:
        10 of (sus_*)
}
