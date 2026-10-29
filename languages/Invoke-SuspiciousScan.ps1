<#
.SYNOPSIS
    ITzMeow80 — snippet di esempio in PowerShell
    Scansione veloce di processi e DLL sospette su Windows.

.DESCRIPTION
    Elenca i processi con moduli non firmati o percorsi inquietanti
    e produce un report sintetico in console.

.EXAMPLE
    .\Invoke-SuspiciousScan.ps1 -Top 10
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$Top = 20,

    [Parameter()]
    [switch]$ExportCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Percorsi considerati sospetti se caricati da processi non di sistema
$SuspiciousPaths = @(
    '\Temp\'
    '\AppData\Local\Temp\'
    '\Downloads\'
    '\Public\'
    '\ProgramData\'
)

function Test-Authenticode {
    <#
        .SYNOPSIS
            Restituisce $true se tutti i moduli del processo sono firmati.
    #>
    param([Parameter(Mandatory)] [System.Diagnostics.Process]$Process)

    try {
        $modules = Get-Process -Id $Process.Id -Module -ErrorAction Stop
    }
    catch {
        return $false   # accesso negato o processo 32/64-bit misto
    }

    foreach ($module in $modules) {
        $file = $module.FileName
        if (-not (Test-Path -LiteralPath $file)) { continue }
        $signature = Get-AuthenticodeSignature -FilePath $file
        if ($signature.Status -ne 'Valid') {
            return $false
        }
    }
    return $true
}

function Find-SuspiciousProcess {
    [OutputType([pscustomobject])]
    cmdletbinding()
    param()

    $results = foreach ($process in Get-Process) {
        $path = try { $process.Path } catch { $null }
        if (-not $path) { continue }

        $inSuspiciousPath = $SuspiciousPaths | Where-Object { $path -like "*$_*" }
        $unsigned = -not (Test-Authenticode -Process $process)

        if ($inSuspiciousPath -or $unsigned) {
            [pscustomobject]@{
                Name        = $process.ProcessName
                Id          = $process.Id
                Path        = $path
                Unsigned    = $unsigned
                RiskyPath   = [bool]$inSuspiciousPath
                Handles     = $process.HandleCount
            }
        }
    }

    $results | Sort-Object -Property @{ Expression = 'RiskyPath'; Descending = $true },
                                     @{ Expression = 'Unsigned';  Descending = $true }
}

try {
    Write-Host "[*] Scansione processi in corso..." -ForegroundColor Cyan
    $findings = Find-SuspiciousProcess | Select-Object -First $Top

    if (-not $findings) {
        Write-Host "[+] Nessun processo sospetto trovato." -ForegroundColor Green
        return
    }

    Write-Host ("[!] Trovati {0} processi da verificare:" -f @($findings).Count) -ForegroundColor Yellow
    $findings | Format-Table -AutoSize

    if ($ExportCsv) {
        $out = Join-Path $PSScriptRoot ('suspicious-processes-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date))
        $findings | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
        Write-Host "[*] Report esportato in: $out" -ForegroundColor Cyan
    }
}
catch {
    Write-Error ("Errore durante la scansione: {0}" -f $_.Exception.Message)
}
