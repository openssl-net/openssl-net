@SETLOCAL
@SET THIS=%0
@SET THIS_DIR=%~dp0

@SET TOOLS=%THIS_DIR%\..\tools
@SET NUGET=%TOOLS%\nuget\nuget.exe


@FOR /F "usebackq delims==" %%f IN (`dir /b/o-n "%THIS_DIR%\ManagedOpenSsl.*.nupkg"`) DO @(
	"%NUGET%" push %%f
	@GOTO :eof
)
