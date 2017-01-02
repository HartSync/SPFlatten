SPFlatten
=========

Flatten SPF records

The Sender Policy Framework has a limit as to how many DNS calls a SPF client can make before the protocol fails open. Many large email providers have a hard time coming under that 10 DNS call limit due to the complex nature of their email sending infrastructure. 

This script is based on the Original Project by Nops @https://github.com/0x9090

This script will recursively resolve the SPF records for a given domain, and flatten the INCLUDE, A, and MX records down to their respective IP4 or IP6 addresses, then further splits the output in sub-domains based on the UDP size limit. This will drastically reduce the DNS calls to come in under the SPF limit. Only compatible with SPFv1.


CLI Usage Example:
====================
    ./SPFlatten.py google.com


Output:
-------

    google.com:

    v=spfv1 ip4:66.249.80.0/20 ip6:2c0f:fb50:4000::/36 ip4:209.85.128.0/17 ip4:64.18.0.0/20 ip4:207.126.144.0/20 ip4:216.58.192.0/19 ip6:2800:3f0:4000::/36 ip4:108.177.8.0/21 ip4:173.194.0.0/16 ip4:64.233.160.0/19 ip4:216.239.32.0/19 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ip6:2a00:1450:4000::/36 ip4:74.125.0.0/16 include:spf1.google.com ~all


    spf1.google.com:

    v=spf1 ip4:72.14.192.0/18 ip4:66.102.0.0/20 ip4:172.217.0.0/19 ~all



For Json Output use:

    ./SPFlatten.py google.com -j 

Output:
-------

    '{"google.com": "v=spfv1 ip4:66.102.0.0/20 ip4:74.125.0.0/16 ip4:173.194.0.0/16 ip4:207.126.144.0/20 ip4:64.18.0.0/20 ip6:2a00:1450:4000::/36
    ip4:172.217.0.0/19 ip6:2c0f:fb50:4000::/36 ip6:2800:3f0:4000::/36 ip4:64.233.160.0/19 ip6:2001:4860:4000::/36 ip4:216.58.192.0/19 ip6:2404:68
    00:4000::/36 ip4:209.85.128.0/17 ip6:2607:f8b0:4000::/36 ip4:108.177.8.0/21 ip4:216.239.32.0/19 ip4:66.249.80.0/20 include:spf1.google.com ~a
    ll", "spf1.google.com": "v=spf1 ip4:72.14.192.0/18 ~all"}'


Python Class Usage Example:
============================

    from SPFlatten import SPFlatten

    spf = SPFlatten(root_domain='google.com')
    
    spf.Outputs()

Output:
-------

    google.com:

    v=spfv1 ip4:66.249.80.0/20 ip6:2c0f:fb50:4000::/36 ip4:209.85.128.0/17 ip4:64.18.0.0/20 ip4:207.126.144.0/20 ip4:216.58.192.0/19 ip6:2800:3f0:4000::/36 ip4:108.177.8.0/21 ip4:173.194.0.0/16 ip4:64.233.160.0/19 ip4:216.239.32.0/19 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ip6:2a00:1450:4000::/36 ip4:74.125.0.0/16 include:spf1.google.com ~all


    spf1.google.com:

    v=spf1 ip4:72.14.192.0/18 ip4:66.102.0.0/20 ip4:172.217.0.0/19 ~all



SPFlatten - AWS Lambda
======================

A Lambda version of this project sits within the  **aws-lambda** folder.

**Usage:**

_Open_ **main.py** & _Set_ **domain** variable to your preferred domain. **NOTE: ** The Domain must exist on Route53 of the AWS account you are running lambda.

    zip -r9 lambda.zip ./project_dir/*

_Configure Lambda Function Using_: **main.handler**

**NOTE:** This function will create TXT records containing flattened SPFs. If a record of the same name and similiar content exists, it will be overwritten.
