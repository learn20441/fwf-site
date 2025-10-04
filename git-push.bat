@echo off
echo === FWF Site Git Push Script ===
cd /d "d:\fwf-site_0.2_vercel\fwf-site"
echo Current directory: %cd%

echo.
echo === Checking Git Status ===
git status

echo.
echo === Adding all changes ===
git add .

echo.
echo === Changes to be committed ===
git status --short

echo.
set /p commit_message="Enter commit message (or press Enter for default): "
if "%commit_message%"=="" set commit_message=Update files - %date% %time%

echo.
echo === Committing with message: %commit_message% ===
git commit -m "%commit_message%"

echo.
echo === Pushing to remote repository ===
git push

echo.
echo === Push completed! ===
pause