@SETLOCAL
@SET THIS=%0
@SET THIS_DIR=%~dp0

@SET TOOLS=%THIS_DIR%\..\tools
@SET NUGET=%TOOLS%\nuget\nuget.exe

"%NUGET%" pack ManagedOpenSsl.csproj -Prop Configuration=Release