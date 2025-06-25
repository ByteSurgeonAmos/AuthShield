@echo off
echo Resetting database tables to fix foreign key issues...
echo.

REM Extract database connection details from .env file
for /f "tokens=2 delims==" %%a in ('findstr "DATABASE_URL" .env') do set DATABASE_URL=%%a

REM Check if DATABASE_URL is found
if "%DATABASE_URL%"=="" (
    echo ERROR: DATABASE_URL not found in .env file
    pause
    exit /b 1
)

echo Found DATABASE_URL: %DATABASE_URL%
echo.

REM Parse the connection string to extract components
REM Format: postgresql://username:password@host:port/database?params

echo Connecting to database to reset tables...
echo.

REM Run the reset script using psql
psql "%DATABASE_URL%" -f reset-tables.sql

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✓ Database tables reset successfully!
    echo ✓ You can now start your NestJS application
    echo.
    echo Run: npm run start:dev
) else (
    echo.
    echo ✗ Failed to reset database tables
    echo Please check your database connection and try again
)

echo.
pause
