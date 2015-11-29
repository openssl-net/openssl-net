
@SETLOCAL
@SET THIS=%0
@SET THIS_DIR=%~dp0

@REM Package up the 32-bit version
@SET SRC=%THIS_DIR%bin\x32\Release
@SET NTV=x86
@SET TGT=%THIS_DIR%dist\tmp32
@CALL :sub_copy

@REM Package up the 64-bit version
@SET SRC=%THIS_DIR%bin\x64\Release
@SET NTV=x64
@SET TGT=%THIS_DIR%dist\tmp64
@CALL :sub_copy

@REM Goto the end of the script
@GOTO :eof


:sub_copy
@ECHO "Bundling %SRC%:

@IF EXIST %TGT% @RMDIR /s /q %TGT%
@MKDIR %TGT%
@MKDIR %TGT%\%NTV%

@COPY "%SRC%\ManagedOpenSsl*.dll"  %TGT%
@COPY "%SRC%\ManagedOpenSsl*.xml"  %TGT%
@COPY "%SRC%\openssl*+.exe"        %TGT%
@COPY "%SRC%\%NTV%\libeay32*.dll"  %TGT%\%NTV%
@COPY "%SRC%\%NTV%\ssleay32*.dll"  %TGT%\%NTV%

@COPY "%THIS_DIR%COPYING*"  "%TGT%"
@COPY "%THIS_DIR%README*"   "%TGT%"
@COPY "%THIS_DIR%INSTALL*"  "%TGT%"
@COPY "%THIS_DIR%LICENSE*"  "%TGT%"
@COPY "%THIS_DIR%CHANGES*"  "%TGT%"

@ECHO DONE
@ECHO.
@REM Return to the caller
@GOTO :eof
