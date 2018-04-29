rule pstore_access
{
strings:
    $ = "pstorec.dll" wide ascii
    $ = "PStoreCreateInstance" wide ascii
condition:
    uint16(0) == 0x5a4d and 2 of them
}
