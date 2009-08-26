set SRC=bin\Release
set TGT=dist

mkdir %TGT%
copy %SRC%\ManagedOpenSsl.dll %TGT%
copy %SRC%\ManagedOpenSsl.xml %TGT%
copy %SRC%\libeay32.dll %TGT%
copy %SRC%\ssleay32.dll %TGT%
copy %SRC%\test.exe %TGT%
copy "%SRC%\openssl+.exe" %TGT%

