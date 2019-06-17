# redundantserializer
A Golang serializer/deserializer with intentional vulnerabilities. Please don't use this for anything but educational purposes!

redundantserializer was created as part of [Pretty Vulnerable Go Application](https://github.com/empayne/pvga), a project that demonstrates the OWASP Top 10 2017 application security risks.

redundantserializer contains an instance of Insecure Deserialization (#8), and formerly contained an instance of XML External Entities (#4). The XXE flaw was patched in order to demonstrate Using Components with Known Vulnerabilities (#9) in pvga.


Search for "OWASP" in the source code for more details. Requires libxml2 to run.
