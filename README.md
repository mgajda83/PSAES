# PSAES
AES encryption module.

# .EXAMPLE

$Message = "A secret Message"

$Result = Protect-AESMessage -Message $Message -Password "A Secret Password" -Salt @(1,2,3,4,5,6,7,9,10,11,252,253,254)

$Result

-----------------
$Result = "WdwAzBT1QZ5njJAJQ8yM6xKBP+iuq87MJP70AuIyD/A="

Unprotect-AESMessage -Message $Result -Password "A Secret Password" -Salt @(1,2,3,4,5,6,7,9,10,11,252,253,254)
