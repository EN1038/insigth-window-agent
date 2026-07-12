; Inno Setup installer for SOSECURE Threat inSight (Go rewrite)
; Builds a Next/Finish wizard setup.exe that:
; - Installs files to {pf}\SOSECURE Threat inSight
; - Registers + starts Windows service
; - Adds Start Menu + Desktop shortcuts
; - Launches UI after install (optional)

[Setup]
AppId={{0B3B5B0A-1D63-4C3E-9B49-3B0E1D38B6C7}
AppName=SOSECURE Threat inSight
AppVersion=4
AppPublisher=SOSECURE
DefaultDirName={pf}\SOSECURE Threat inSight
DefaultGroupName=SOSECURE Threat inSight
DisableProgramGroupPage=yes
OutputBaseFilename=insite-installer
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
WizardStyle=modern

; Use legacy app icon for installer + ARP entry.
SetupIconFile=..\..\insite_old\insite\app.ico
UninstallDisplayIcon={app}\app.ico

[Files]
; Main executable (built from go-agent)
Source: "..\dist\insite-setup.exe"; DestDir: "{app}"; DestName: "insite-agent.exe"; Flags: ignoreversion

; App icon (for shortcuts + Add/Remove Programs display icon)
Source: "..\..\insite_old\insite\app.ico"; DestDir: "{app}"; Flags: ignoreversion

; Optional: include Engine folder if you ship yara64.exe/rules beside exe
; Source: "..\dist\Engine\*"; DestDir: "{app}\Engine"; Flags: ignoreversion recursesubdirs createallsubdirs

[Run]
; Install service (runs as admin because installer is admin)
Filename: "{app}\insite-agent.exe"; Parameters: "-mode install"; Flags: runhidden waituntilterminated

; Seal local data (encrypt rules, harden ACLs, remove plaintext leftovers)
Filename: "{app}\insite-agent.exe"; Parameters: "-mode seal"; Flags: runhidden waituntilterminated

; Launch UI after install
Filename: "{app}\insite-agent.exe"; Parameters: "-mode ui"; Flags: nowait postinstall skipifsilent

[Icons]
Name: "{group}\SOSECURE Threat inSight"; Filename: "{app}\insite-agent.exe"; Parameters: "-mode ui"; IconFilename: "{app}\app.ico"
Name: "{group}\{cm:UninstallProgram,SOSECURE Threat inSight}"; Filename: "{uninstallexe}"; IconFilename: "{app}\app.ico"
Name: "{commondesktop}\SOSECURE Threat inSight"; Filename: "{app}\insite-agent.exe"; Parameters: "-mode ui"; Tasks: desktopicon; IconFilename: "{app}\app.ico"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[UninstallRun]
; Stop and remove the Go agent service before deleting files.
Filename: "{app}\insite-agent.exe"; Parameters: "-mode uninstall"; Flags: runhidden waituntilterminated

