$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$icoPath = Join-Path $dir "TunGuard.ico"
$exePath = Join-Path $dir "TunGuard.exe"
$srcPath = Join-Path $dir "TunGuard.cs"
$manifestPath = Join-Path $dir "app.manifest"

# 1. Generate a crisp 48x48 multi-color shield icon (.ico) for the EXE and Desktop shortcut
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 48, 48
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::Transparent)

$shield = [System.Drawing.PointF[]]@(
    (New-Object System.Drawing.PointF 24, 3),
    (New-Object System.Drawing.PointF 42, 9.5),
    (New-Object System.Drawing.PointF 39.5, 28),
    (New-Object System.Drawing.PointF 24, 45),
    (New-Object System.Drawing.PointF 8.5, 28),
    (New-Object System.Drawing.PointF 6, 9.5)
)
$brush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(22, 163, 74))
$pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(15, 118, 52)), 3.0
$g.FillPolygon($brush, $shield)
$g.DrawPolygon($pen, $shield)

$tPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), 4.5
$tPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$tPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$g.DrawLine($tPen, 15.5, 16.5, 32.5, 16.5)
$g.DrawLine($tPen, 24.0, 16.5, 24.0, 33.5)

$msPng = New-Object System.IO.MemoryStream
$bmp.Save($msPng, [System.Drawing.Imaging.ImageFormat]::Png)
$pngBytes = $msPng.ToArray()

# Write standard PNG-in-ICO container (supported natively since Windows Vista)
$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([uint16]0)       # Reserved
$bw.Write([uint16]1)       # Type = ICO
$bw.Write([uint16]1)       # Image count = 1
$bw.Write([byte]48)        # Width
$bw.Write([byte]48)        # Height
$bw.Write([byte]0)         # Color palette
$bw.Write([byte]0)         # Reserved
$bw.Write([uint16]1)       # Color planes
$bw.Write([uint16]32)      # Bits per pixel
$bw.Write([uint32]$pngBytes.Length)
$bw.Write([uint32]22)      # Offset to PNG data
$bw.Write($pngBytes)
$bw.Dispose()
$fs.Dispose()
$msPng.Dispose()
$tPen.Dispose()
$pen.Dispose()
$brush.Dispose()
$g.Dispose()
$bmp.Dispose()

# 2. Compile TunGuard.exe (x64, native winexe, zero external dependencies)
& $csc `
    /nologo `
    /target:winexe `
    /platform:x64 `
    /optimize+ `
    /utf8output `
    "/win32icon:$icoPath" `
    "/win32manifest:$manifestPath" `
    "/out:$exePath" `
    /r:System.dll `
    /r:System.Core.dll `
    /r:System.Drawing.dll `
    /r:System.Web.Extensions.dll `
    /r:System.Windows.Forms.dll `
    "$srcPath"

if ($LASTEXITCODE -ne 0) {
    throw "csc.exe failed with exit code $LASTEXITCODE"
}

Write-Host "Built successfully: $exePath ($((Get-Item $exePath).Length) bytes)"
