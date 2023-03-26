This is a Win10 64bit rewrite of the GICPar.sys driver that allows to install the RIC S300EI Parallel port flatbed scanner under windows 10/11
What is does is to allow parallel port access to the original WinNT driver, so the scanner can work, by reimplementing the WinNT driver, to make it compatible with 64bit windows

This files under Output must be copied to 
c:\Windows\twain_32\

Also, you need to install the test certificate under root authority (Gicpar.cer)
Also, you need to run (as administrator) install.bat to install the required new driver.

That is all
