
@SETLOCAL
@SET THIS=%0
@SET THIS_DIR=%~dp0

@SET NUGET_REV=%1
@IF "%NUGET_REV%"=="" SET NUGET_REV=0

@SET TOOLS=%THIS_DIR%..\tools\
@SET NUGET=%TOOLS%nuget\nuget.exe

@SET NUGET_PROPS=id=ManagedOpenSsl
@SET NUGET_PROPS=;Configuration=Release
@SET NUGET_PROPS=%NUGET_PROPS%;nugetRev=.%NUGET_REV%


@SET NUGET_OUT="%THIS_DIR%..\dist\nuget32"
@IF EXIST %NUGET_OUT% RMDIR /s/q %NUGET_OUT%
@MKDIR %NUGET_OUT%
"%NUGET%" pack "%THIS_DIR%ManagedOpenSsl.csproj" -Prop "%NUGET_PROPS%;Platform=x32;idSuffix=32" -Out %NUGET_OUT%

@SET NUGET_OUT="%THIS_DIR%..\dist\nuget64"
@IF EXIST %NUGET_OUT% RMDIR /s/q %NUGET_OUT%
@MKDIR %NUGET_OUT%
"%NUGET%" pack "%THIS_DIR%ManagedOpenSsl.csproj" -Prop "%NUGET_PROPS%;Platform=x64;idSuffix=" -Out %NUGET_OUT%
