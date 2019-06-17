# redundantserializer
A Golang serializer/deserializer with intentional vulnerabilities. Please don't use this for anything but educational purposes!

redundantserializer was created as part of [Pretty Vulnerable Go Application](https://github.com/empayne/pvga), a project that demonstrates the OWASP Top 10 2017 application security risks.
This project contains instances of XML External Entities (#4) and Insecure Deserialization (#8).
Search for "OWASP" in the source code for more details.

Requires libxml2 to run.
