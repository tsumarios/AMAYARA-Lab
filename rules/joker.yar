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
    $payload = { 6173736574732f36327672723571717136 } // assets/62vrr5qqq6
    $net1 = "MF8zXzEgbGlrZSBNYWMgT1MgWCkgQXBwbGVXZWJLaXQvNjAzLjEuMzAgKEtIVE1MLCBs" // s://fibvdk77pp.s3.us-east-1.amazonaws.com/agfwot6tm1
    $net2 = { 68747470733a2f2f637574742e6c792f6c4173634762304e64 }  // https://cutt.ly/lAscGb0Nd
  
  condition:
    (uint16be(0) == 0x504b and $payload) or ($net1 or $net2)
}