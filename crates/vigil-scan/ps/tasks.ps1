# Scheduled tasks (read-only).
param([Parameter(Mandatory = $true)][string]$OutPath)
. "$PSScriptRoot\_common.ps1"

function Get-ComServer {
    # Returns the binary that implements a CLSID (tasks with a "COM handler" action).
    param([string]$ClassId)
    if (-not $ClassId) { return $null }
    foreach ($root in 'HKEY_CLASSES_ROOT\CLSID', 'HKEY_CLASSES_ROOT\Wow6432Node\CLSID') {
        foreach ($sub in 'InprocServer32', 'LocalServer32') {
            try {
                $v = [Microsoft.Win32.Registry]::GetValue("$root\$ClassId\$sub", '', $null)
                if ($v) { return [string]$v }
            } catch { }
        }
    }
    return $null
}

$tasks = @()
try {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $t = $_
        $actions = @($t.Actions | ForEach-Object {
            $a = $_
            $class = $a.CimClass.CimClassName
            if ($class -eq 'MSFT_TaskExecAction') {
                @{ type = 'exec'; exe = $a.Execute; args = $a.Arguments; cwd = $a.WorkingDirectory }
            } elseif ($class -eq 'MSFT_TaskComHandlerAction') {
                @{ type = 'com'; clsid = $a.ClassId; server = (Get-ComServer $a.ClassId) }
            } else {
                @{ type = $class }
            }
        })
        $triggers = @($t.Triggers | ForEach-Object {
            ($_.CimClass.CimClassName -replace '^MSFT_Task', '') -replace 'Trigger$', ''
        })

        $lastRun = $null
        $lastResult = $null
        if ($t.TaskPath -notlike '\Microsoft\*') {
            try {
                $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop
                $lastRun = ConvertTo-Iso $info.LastRunTime
                $lastResult = $info.LastTaskResult
            } catch { }
        }

        @{
            name        = $t.TaskName
            path        = $t.TaskPath
            state       = [string]$t.State
            author      = $t.Author
            date        = $t.Date
            desc        = $t.Description
            user        = $t.Principal.UserId
            group       = $t.Principal.GroupId
            runlevel    = [string]$t.Principal.RunLevel
            hidden      = [bool]$t.Settings.Hidden
            actions     = $actions
            triggers    = $triggers
            last_run    = $lastRun
            last_result = $lastResult
        }
    })
} catch { Add-Note 'tasks' $_.Exception.Message }

Write-JsonFile $OutPath @{ tasks = $tasks; notes = @($script:Notes) }
