rule SuppressIldasmAttribute
{
strings:
    $ = "SuppressIldasmAttribute" wide ascii
condition:
    uint16(0) == 0x5a4d and any of them
}
