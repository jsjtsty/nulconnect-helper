param(
    [ValidateSet("version", "status", "start_tun", "stop_tun", "shutdown")]
    [string]$Command = "status",
    [string]$ConfigJsonPath
)

$ErrorActionPreference = "Stop"
$request = [ordered]@{ id = [guid]::NewGuid().ToString(); command = $Command }
if ($Command -eq "start_tun") {
    if (-not $ConfigJsonPath) { throw "start_tun requires -ConfigJsonPath" }
    $request.config = Get-Content -LiteralPath $ConfigJsonPath -Raw | ConvertFrom-Json
}
$json = ($request | ConvertTo-Json -Depth 20 -Compress)
$client = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'NulConnectHelper', [System.IO.Pipes.PipeDirection]::InOut)
$client.Connect(5000)
try {
    $writer = [System.IO.StreamWriter]::new($client)
    $writer.AutoFlush = $true
    $reader = [System.IO.StreamReader]::new($client)
    $writer.Write($json)
    $response = $reader.ReadToEnd()
    if ($response) { $response | ConvertFrom-Json | ConvertTo-Json -Depth 20 }
}
finally { $client.Dispose() }
