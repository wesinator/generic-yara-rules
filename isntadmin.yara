rule IsNTAdmin {
    meta:
        reference = "http://www.sgr.info/dev/win32api/IsNTAdmin.htm"
    strings:
        $ = "advpack.dll\x00IsNTAdmin" wide ascii
    condition:
        uint16(0) == 0x5a4d and any of them
}
