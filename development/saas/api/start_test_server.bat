@echo off
REM Start API Server for Testing
REM Uses test database and clears Redis password for no-auth connection

set DATABASE_URL=postgresql://postgres:postgres@localhost:5433/test_saas
set TESTING_MODE=true
set PORT=8001
set REDIS_HOST=localhost
set REDIS_PORT=6379
set REDIS_PASSWORD=

echo Starting API server on port 8001 with test configuration...
echo Database: %DATABASE_URL%
echo Redis: %REDIS_HOST%:%REDIS_PORT% (no password)
echo.

python -m uvicorn saas_server:app --host 0.0.0.0 --port 8001 --reload
