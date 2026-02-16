@echo off
REM Start the Go microservice (requires Go installed and in PATH)
cd /d "%~dp0\go_service"
go run main.go
