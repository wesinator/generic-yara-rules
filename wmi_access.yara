rule WMI_access
{
    strings:
        $c0 = "root/cimv2" wide ascii
        $c1 = "ROOT/CIMV2" wide ascii
        $c2 = "root\\cimv2" wide ascii
        $c3 = "ROOT\\CIMV2" wide ascii
    condition:
        uint16(0) == 0x5a4d and any of them
}
