# FWF Site Git Push Script for PowerShell
Write-Host "=== FWF Site Git Push Script ===" -ForegroundColor Green

# Change to correct directory
Set-Location "d:\fwf-site_0.2_vercel\fwf-site"
Write-Host "Current directory: $(Get-Location)" -ForegroundColor Yellow

# Check git status
Write-Host "`n=== Checking Git Status ===" -ForegroundColor Cyan
git status

# Add all changes
Write-Host "`n=== Adding all changes ===" -ForegroundColor Cyan
git add .

# Show staged changes
Write-Host "`n=== Changes to be committed ===" -ForegroundColor Cyan
git status --short

# Get commit message
$commitMessage = Read-Host "`nEnter commit message (or press Enter for default)"
if ([string]::IsNullOrWhiteSpace($commitMessage)) {
    $commitMessage = "Update files - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
}

# Commit changes
Write-Host "`n=== Committing with message: $commitMessage ===" -ForegroundColor Cyan
git commit -m $commitMessage

# Push to remote
Write-Host "`n=== Pushing to remote repository ===" -ForegroundColor Cyan
git push

Write-Host "`n=== Push completed! ===" -ForegroundColor Green
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")