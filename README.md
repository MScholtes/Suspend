# Suspend
C++ command line tool to suspend / resume processes (Windows)

<b>How To Compile</b>

- Start Visual Studio command prompt<br />
- Change to directory with Suspend.cpp<br />
- compile with cl Suspend.cpp<br />

<b>Usage</b>

Suspend [parameter] [PID or program name]<br />
Suspends process(es) oder resumes them.<br /> 
The operating system has a suspend counter, a process has to be resumed as often as it was suspended.<br />
Instead of a complete program name a starting part of the name can be supplied. Only the first found process is processed (see parameter /INSTANCE).<br />

Parameter:<br />
/INSTANCE:n - process n. found process with name part (default: 1).<br />
/INSTANCE:ALL - process all found processes with name part. The parameter /INSTANCE: can be shortened by /I:.<br />
/SUSPEND oder /S - suspend process(es) (default action).<br />
/RESUME oder /R - resume process(es).<br />

<b>Examples</b>

suspend 1324<br />
Suspends process with ID 1324<br />

suspend /r notep<br />
Resumes first found notepad process<br />
