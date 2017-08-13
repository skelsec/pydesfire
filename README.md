pyDESFire
=========

Desfire card library for Python

WARNING
=======

Project still ongoing, use it with caution!

Features
========

-   Compatible with all readers supported by pySCARD

-   Pure python implementation

-   One of the few DESFire libraries that supports ALL (DES,2DES,3DES,AES)
    authentication types

-   Enumeration of the card gives an overlook on how the card is structured

Issues
======

-   CMAC calculation fails (this causes the IV for the session key to lose sync
    with the IV on the card)

-   Encrypted communication is not implemented (need to fix CMAC first)

-   Can’t read data from certain file types

-   Some commands are missing (since there is no full documentation available)

Author
======

Tamas Jos

Credits
=======

The codebase of this project was based on two major projects:

Elmue 
------

>   who created a completely working DESFireEV1 library. (this module is based
>   99% of his work!)

>   URL:
>   https://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup

miohtama (https://twitter.com/moo9000)
--------------------------------------

>   who worte the original desfire module for python.

>   URL: <https://github.com/miohtama/desfire/>
