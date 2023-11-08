set servicesStopList=PlugPlay, Spooler
set servicesStartList=
set windowsUpdateServices=wuauserv


:disableService 
sc config %~1 start=disabled
if ERRORLEVEL 1 echo Unable to disable %~1. Check to see if it is already disabled. 
   pause 
exit /b 0 

for %%i in (%servicesStopList%) do (
   call :stopService %%i 
   call :disableService %%i 
) 
exit /b 0

:stopService 
sc stop %~1
if ERRORLEVEL 1 echo Unable to stop %~1. Check to see if it is already stopped. 
   pause 
exit /b 0 