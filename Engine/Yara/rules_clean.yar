rule SOSECURE_Rule_Test
{
    meta:
        description = "Test rule for SOSECURE YARA Scanner"
        author = "SOSECURE"
    strings:
        $a = "SOSECURE_TEST_MALWARE"
    condition:
        $a
}

rule PHP_HTTPFlood_ChickenX
{
    meta:
        description = "Detects ChickenX HTTP Flood PHP script"
        author = "Antigravity"
    strings:
        $s1 = "ChickenX"
        $s2 = "HTTP flood complete after"
        $s3 = "fsockopen"
    condition:
        2 of ($s*)
}

rule PHP_Generic_Flood
{
    meta:
        description = "Detects generic PHP flood scripts"
        author = "Antigravity"
    strings:
        $f1 = "fsockopen"
        $f2 = "ignore_user_abort"
        $f3 = "set_time_limit(0)"
        $p1 = "$_GET['ip']"
        $p2 = "$_GET['time']"
    condition:
        all of ($f*) and 1 of ($p*)
}
