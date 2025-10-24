@echo off
REM ML-SecTest Kubernetes Port-Forward Management (Windows Wrapper)
REM Usage: k8s-port-forward.bat [start|stop|status|restart]

bash "%~dp0k8s-port-forward.sh" %*
