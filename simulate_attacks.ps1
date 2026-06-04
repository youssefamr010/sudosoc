# SUDOSOC Attack Simulation Script
# ---------------------------------------------------------
# This script generates network patterns for testing the IDS.
# RUN AS ADMINISTRATOR for best results.
# ---------------------------------------------------------

function Show-Menu {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "   IDS/IPS ATTACK TRAFFIC SIMULATOR       " -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "1. Port Scan Simulation (Reconnaissance)"
    Write-Host "2. DoS/Flood Simulation (Denial of Service)"
    Write-Host "3. C2 Beaconing (Suspicious Port Activity)"
    Write-Host "4. Data Exfiltration (High Volume Flow)"
    Write-Host "5. Exit"
    Write-Host "==========================================" -ForegroundColor Cyan
}

while ($true) {
    Show-Menu
    $choice = Read-Host "Select an attack to simulate"

    switch ($choice) {
        "1" {
            Write-Host "[!] Simulating Port Scan on Localhost..." -ForegroundColor Yellow
            $ports = 20..100 + 443..450 + 3389
            foreach ($port in $ports) {
                Write-Host "Testing Port: $port"
                $t = New-Object Net.Sockets.TcpClient
                $t.ConnectAsync("127.0.0.1", $port).Wait(50) | Out-Null
                if ($t.Connected) { $t.Close() }
            }
            Write-Host "[+] Port Scan Simulation Complete." -ForegroundColor Green
            Pause
        }

        "2" {
            $targetPort = Read-Host "Enter port to flood (e.g. 80)"
            Write-Host "[!] Simulating DoS Flood on Port $targetPort..." -ForegroundColor Red
            for ($i=1; $i -le 500; $i++) {
                $client = New-Object System.Net.Sockets.TcpClient
                $client.ConnectAsync("127.0.0.1", $targetPort).Wait(10) | Out-Null
                $client.Close()
                if ($i % 50 -eq 0) { Write-Host "Sent $i packets..." }
            }
            Write-Host "[+] DoS Simulation Complete." -ForegroundColor Green
            Pause
        }

        "3" {
            Write-Host "[!] Simulating C2 Beaconing to Suspicious Port 4444..." -ForegroundColor Magenta
            # Connects to a port typically used by Metasploit/Netcat
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                $client.Connect("127.0.0.1", 4444)
                $client.Close()
            } catch {
                Write-Host "Connection attempted (IDS should see the port number even if it fails)."
            }
            Write-Host "[+] C2 Simulation Complete." -ForegroundColor Green
            Pause
        }

        "4" {
            Write-Host "[!] Simulating Large Data Exfiltration..." -ForegroundColor Yellow
            # Generates a high volume flow of "dummy" data
            $data = New-Object Byte[] 1048576 # 1MB
            (New-Object Random).NextBytes($data)
            
            try {
                $stream = [System.Net.Sockets.TcpClient]::new("127.0.0.1", 80).GetStream()
                for ($i=0; $i -lt 10; $i++) {
                    $stream.Write($data, 0, $data.Length)
                    Write-Host "Sent $(($i+1)) MB..."
                }
                $stream.Close()
            } catch {
                Write-Host "Simulation complete (Flow volume recorded)."
            }
            Pause
        }

        "5" { exit }
    }
}
