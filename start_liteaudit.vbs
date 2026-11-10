' start_liteaudit.vbs - starts the LiteAudit app and the quarantine watcher
' in hidden windows. Keep this file in the same folder as liteaudit_app.py.
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
shell.CurrentDirectory = fso.GetParentFolderName(WScript.ScriptFullName)

' 0 = hidden window, False = don't wait for it to finish
shell.Run "python quarantine_watcher.py", 0, False
shell.Run "python -m streamlit run liteaudit_app.py --server.headless true --server.address 127.0.0.1 --server.port 8501", 0, False
