Option Explicit

Dim sh, fso, root, bat, comspec, cmd, status
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
bat = fso.BuildPath(root, "start.bat")

If Not fso.FileExists(bat) Then
  MsgBox "Launcher not found:" & vbCrLf & bat, 16, "OpenAI Reauth"
  WScript.Quit 1
End If

sh.CurrentDirectory = root
comspec = sh.ExpandEnvironmentStrings("%ComSpec%")
sh.Environment("PROCESS")("OPENAI_REAUTH_START") = bat
cmd = """" & comspec & """ /d /v:off /s /c """"%OPENAI_REAUTH_START%"""""
status = sh.Run(cmd, 1, True)
If status <> 0 Then
  MsgBox "OpenAI Reauth could not start. See:" & vbCrLf & fso.BuildPath(root, "gui-error.log"), 16, "OpenAI Reauth"
End If
WScript.Quit status
