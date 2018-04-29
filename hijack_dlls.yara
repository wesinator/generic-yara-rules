rule fxsst_dll
{
meta:
    reference = "https://www.fireeye.com/blog/threat-research/2011/06/fxsst.html"
strings:
    $f = "fxsst.dll" fullword wide ascii
condition:
    uint16(0) == 0x5a4d and any of them
}

rule ntshrui_dll
{
meta:
    reference = "https://www.mandiant.com/blog/malware-persistence-windows-registry/"
strings:
    $n = "ntshrui.dll" fullword wide ascii
condition:
    uint16(0) == 0x5a4d and any of them
}
