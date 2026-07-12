rule SOSECURE_Rule_Test
{
    condition:
        false
}

rule PHP_HTTPFlood_ChickenX
{
    strings:
        $s1 = "ChickenX"
        $s2 = "P-Flood"
        $s3 = "fsockopen"
    condition:
        2 of ($s*)
}

rule PHP_Generic_Flood
{
    strings:
        $f1 = "fsockopen"
        $f2 = "fputs"
        $p1 = "GET /"
        $p2 = "POST /"
    condition:
        all of ($f*) and 1 of ($p*)
}
