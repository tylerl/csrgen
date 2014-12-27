# CSR Generator

Everybody knows you should only generate CSRs on your local computer. But OpenSSL is hard to use.

This script runs a local webserver which creates a simple to use interface for your local installation of OpenSSL.

This works on POSIX systems only which have OpenSSL already installed. So basically OSX, Linux, BSD, etc. Everything but Windows.

Only `csrgen.py` is required. `staticgen.py` gets used to text-encode the `static` directory
to it into `csrgen.py`.