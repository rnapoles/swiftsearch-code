@SetLocal
	@Echo Off
	Set "DIR=%~dp1en-US"
	MkDir "%DIR%" 2>NUL
	Del "%~dpn1.ln%~x1"
	Del "%DIR%\%~n1.ln%~x1.mui"
	MUIRCT -q MUIConfig.xml -g "%~4" -x "%~4" "%~1" "%~dpn1.ln%~x1" "%DIR%\%~n1%~x1.mui" && Del "%~dpn1.ln%~x1"
	Path %PATH%;%ProgramFiles%\Resource Hacker;%ProgramFiles(x86)%\Resource Hacker
	If "%~3" == "x64" (
		EditBin /NoLogo "%~1" /Subsystem:Windows,5.02 /OSVersion:5.1
	) Else (
		EditBin /NoLogo "%~1" /Subsystem:Windows,5.01 /OSVersion:4
		If Not "%~1" == "%~5" (
			1>&2 Echo Embedding 64-bit version...
			ResHacker -addoverwrite "%~1", "%~1", "%~5", BINARY, "AMD64", "%~4"
		)
	)
@EndLocal