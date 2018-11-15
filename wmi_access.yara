rule WMI_access
{
    strings:
        $ = /(root|ROOT)[\/\\](cimv|CIMV)2/ wide ascii
    condition:
        uint16(0) == 0x5a4d and any of them
}

