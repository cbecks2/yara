import "pe"

rule gen_possible_fake_excel_dna_xll
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-04-15"
        desc = "This is a generic/fragile rule that hopes to find XLL files that masquerade as being developed for Excel-DNA but do not match known patterns.."
        reference = "https://forensicitguy.github.io/extracting-payloads-excel-dna-xlls/"
        reference_inspiration = "Greg Lesnewich's #100daysofYara Project"

    condition:
         uint16(0) == 0x5a4d
         and filesize < 8MB
         //and pe.exports("xlAutoOpen") //required for XLLs
         and (
             (pe.dll_name icontains "ExcelDna.xll" //default for ExcelDNA
             or pe.dll_name icontains "ExcelDna64.xll" //default for ExcelDNA
             )

             or pe.exports("CalculationCanceled") //default export for ExcelDNA
             or pe.exports("CalculationEnded") //default export for ExcelDNA
             or pe.exports("SyncMacro") //default export for ExcelDNA
         )
         and not (
             (pe.version_info["OriginalFilename"] == "ExcelDna.xll"
             and pe.version_info["InternalName"] == "ExcelDna"
             and pe.version_info["ProductName"] == "Excel-DNA Add-In Framework for Microsoft Excel"
             and pe.version_info["FileDescription"] == "Excel-DNA Dynamic Link Library"
             //and pe.number_of_exports < 10
             //and pe.number_of_resources < 1
             )
         )
}
