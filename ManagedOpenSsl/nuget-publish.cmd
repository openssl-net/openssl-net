@SETLOCAL
@SET THIS=%0
@SET THIS_DIR=%~dp0

@SET TOOLS=%THIS_DIR%\..\tools
@SET NUGET=%TOOLS%\nuget\nuget.exe

@SET NUGET_OUT="%THIS_DIR%..\dist\"

@FOR /F "usebackq delims==" %%f IN (`dir /s/b/o-n "%NUGET_OUT%*.nupkg"`) DO @(
	"%NUGET%" push %%f
)
