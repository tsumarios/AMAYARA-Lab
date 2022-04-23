rule Joker_Payload1: Joker Payload1 {
    meta:
        description = "Koodous Community Public Rule to detect Joker Android malware."
        author      = "kiya"
        date        = "2019-10-17"
        
    strings:
        $net = { 2F6170692F636B776B736C3F6963633D } // /api/ckwksl?icc=   
        $ip = "3.122.143.26"

    condition:
        $net or $ip 
}

rule Joker_Payload2: Joker Payload2 {
  meta:
    description = "Detects Android Joker payloads."
    author      = "tsumarios"
    date        = "2022-04-23"

  strings:
    $payload = { 61 73 73 65 74 73 2f 36 32 76 72 72 35 71 71 71 36 } // assets/62vrr5qqq6
    $net = "MF8zXzEgbGlrZSBNYWMgT1MgWCkgQXBwbGVXZWJLaXQvNjAzLjEuMzAgKEtIVE1MLCBs" // s://fibvdk77pp.s3.us-east-1.amazonaws.com/agfwot6tm1
  
  condition:
    (uint16be(0) == 0x504b and $payload) or ($net)
}