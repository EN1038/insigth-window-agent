; =============================================================================
; SOSECURE Threat inSight — Go Agent Inno Setup
; Target  : Windows Server 2012 R2+ (no .NET 3.5 required)
; Service : SOSECURE Threat inSight (single service)
; =============================================================================

[Setup]
AppId={{A3C8F2E1-9B4D-4E7A-8C1F-2D5E6A9B0C3D}
AppName=SOSECURE Threat inSight
AppVersion=5.7.1.0
AppVerName=SOSECURE Threat inSight 5.7.1 (Go)
AppPublisher=SOSECURE
AppPublisherURL=https://sosecure.co.th/
DefaultDirName={autopf}\SOSECURE\Threat inSight
DefaultGroupName=SOSECURE Threat inSight
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
SetupIconFile=app.ico
UninstallDisplayIcon={app}\app.ico
WizardStyle=modern
LicenseFile=LICENSE.txt
OutputDir=Output
OutputBaseFilename=SOSECURE_Threat_inSight_Go_Setup_v5.7.1
Compression=lzma2/ultra64
SolidCompression=no
MinVersion=6.3

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "thai";    MessagesFile: "compiler:Languages\Thai.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "Launch UI on Windows logon"; GroupDescription: "Options:"; Flags: unchecked

[Files]
Source: "dist\insite-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
; Mesa software OpenGL (llvmpipe) — enables Fyne UI on VMs without GPU OpenGL.
Source: "Engine\Mesa\opengl32.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Engine\Mesa\libgallium_wgl.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Engine\Mesa\insite-agent.exe.local"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "Engine\Yara\yara64.exe"; DestDir: "{app}\Engine\Yara"; Flags: ignoreversion
; Bundled rules are optional — Center sync / sealed store is the source of truth.
Source: "Engine\Yara\rules.yar"; DestDir: "{app}\Engine\Yara"; Flags: ignoreversion skipifsourcedoesntexist
Source: "Engine\Yara\rules_unified.yar"; DestDir: "{app}\Engine\Yara"; Flags: ignoreversion skipifsourcedoesntexist
; Offline ssdeep seed (encrypted into ProgramData on seal / first service start).
Source: "go-agent\bundled\ssdeep\signatures.db"; DestDir: "{app}\bundled\ssdeep"; Flags: ignoreversion skipifsourcedoesntexist
Source: "go-agent\bundled\rules\*"; DestDir: "{app}\bundled\rules"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "app.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "Config\Key\config.json"; DestDir: "{app}\Config\Key"; Flags: onlyifdoesntexist ignoreversion skipifsourcedoesntexist
Source: "Config\Key\client.p12"; DestDir: "{app}\Config\Key"; Flags: ignoreversion skipifsourcedoesntexist
Source: "Config\Key\client.p12"; DestDir: "{commonappdata}\SOSECURE Threat inSight\Config\Key"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\SOSECURE Threat inSight"; Filename: "{app}\insite-agent.exe"; Parameters: "-mode ui"; IconFilename: "{app}\app.ico"
Name: "{group}\{cm:UninstallProgram,SOSECURE Threat inSight}"; Filename: "{uninstallexe}"; IconFilename: "{app}\app.ico"
Name: "{commondesktop}\SOSECURE Threat inSight"; Filename: "{app}\insite-agent.exe"; Parameters: "-mode ui"; IconFilename: "{app}\app.ico"; Tasks: desktopicon
Name: "{userstartup}\SOSECURE Threat inSight"; Filename: "{app}\insite-agent.exe"; Parameters: "-mode ui"; IconFilename: "{app}\app.ico"; Tasks: autostart

[Run]
Filename: "{app}\insite-agent.exe"; Parameters: "-mode upgrade"; StatusMsg: "Installing Windows Service..."; Flags: runhidden waituntilterminated
Filename: "{app}\insite-agent.exe"; Parameters: "-mode seal"; StatusMsg: "Sealing bundled threat intelligence..."; Flags: runhidden waituntilterminated
Filename: "{app}\insite-agent.exe"; Parameters: "-mode ui"; Description: "Open SOSECURE Threat inSight"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\insite-agent.exe"; Parameters: "-mode uninstall"; Flags: runhidden waituntilterminated
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM insite-agent.exe"; Flags: runhidden
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM insight.sosecure.legacy.exe"; Flags: runhidden
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM sosecure-engine.exe"; Flags: runhidden

[UninstallDelete]
; Program files under {app} are removed by Inno automatically.
; Also wipe leftover logs in install dir and persistent ProgramData / per-user runtime.
Type: filesandordirs; Name: "{app}\Logs"
Type: filesandordirs; Name: "{commonappdata}\SOSECURE Threat inSight"
Type: filesandordirs; Name: "{localappdata}\SOSECURE Threat inSight"
Type: filesandordirs; Name: "{userappdata}\SOSECURE Threat inSight"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    { Legacy services stopped by insite-agent.exe -mode upgrade }
  end;
end;
