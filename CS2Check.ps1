#Requires -Version 5.1
<#
    CS2Check - утилита добровольной проверки ПК на следы читов для CS2
    Версия: 1.0

    ЧТО ЭТО
    Скрипт собирает с компьютера игрока криминалистические артефакты Windows,
    которые остаются после запуска сторонних программ, и строит отчёт для
    администратора сервера. Скрипт НИЧЕГО не меняет на компьютере, не ставит
    драйверы, не остаётся в автозагрузке и не отправляет данные без явного
    согласия игрока.

    КАК ЗАПУСКАТЬ (от имени администратора):
        powershell -ExecutionPolicy Bypass -File .\CS2Check.ps1 -Token ABC123

    ВАЖНО: скрипт не должен запускаться после перезагрузки компьютера -
    часть артефактов живёт только до ребута.

    Лицензия: MIT. Делайте форк и дописывайте правила под свой сервер.
#>

[CmdletBinding()]
param(
    # Одноразовый токен, который админ выдаёт игроку перед проверкой.
    # Защищает от повторной отправки старого «чистого» отчёта.
    [string] $Token = '',

    # Куда положить отчёт. По умолчанию - рабочий стол.
    [string] $OutDir = '',

    # URL приёмника отчётов (если есть панель). Пусто = только локальный файл.
    [string] $ServerUrl = '',

    # Пропустить экран согласия. Только для отладки самим админом!
    [switch] $IAgree,

    # Не трогать USN-журнал (сбор может занять 1-3 минуты на больших дисках).
    [switch] $SkipUsn,

    # Тихий режим: не открывать отчёт и не спрашивать про отправку.
    # Включает GUI-обёртка CS2Check.App.ps1, которая делает это сама.
    [switch] $Quiet
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$script:ScriptVersion  = '1.0'
$script:StartedAt      = Get-Date

# ============================================================================
#  ИНФРАСТРУКТУРА
# ============================================================================

$script:Findings      = New-Object System.Collections.ArrayList
$script:FindingIndex  = @{}
$script:Data          = [ordered]@{}
$script:SigCache      = @{}

# Одинаковые находки схлопываем в одну с counter'ом: USN-журнал содержит
# сотни записей про один и тот же файл, и без этого отчёт превращается
# в стену одинаковых карточек.
function Add-Finding {
    param(
        [ValidateSet('High','Medium','Low','Info')][string] $Severity,
        [string] $Category,
        [string] $Title,
        [string] $Detail = '',
        $Evidence = $null
    )
    $key = $Severity + '|' + $Category + '|' + $Title
    if ($script:FindingIndex.ContainsKey($key)) {
        $script:FindingIndex[$key].Hits += 1
        return
    }
    $f = [pscustomobject]@{
        Severity = $Severity
        Category = $Category
        Title    = $Title
        Detail   = $Detail
        Evidence = $Evidence
        Hits     = 1
    }
    $script:FindingIndex[$key] = $f
    [void]$script:Findings.Add($f)
}

function Write-Step {
    param([string] $Text)
    Write-Host ('  [*] ' + $Text) -ForegroundColor DarkGray
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Подпись файла с кэшем - Get-AuthenticodeSignature медленный.
function Get-SigInfo {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'NoPath' }
    if ($script:SigCache.ContainsKey($Path))  { return $script:SigCache[$Path] }
    $result = 'Unknown'
    try {
        if (Test-Path -LiteralPath $Path) {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            if ($s.Status -eq 'Valid') {
                $subject = ''
                if ($s.SignerCertificate) {
                    $subject = ($s.SignerCertificate.Subject -split ',')[0] -replace '^CN=',''
                }
                $result = 'Valid: ' + $subject
            } else {
                $result = [string]$s.Status
            }
        } else {
            $result = 'FileMissing'
        }
    } catch { $result = 'Error' }
    $script:SigCache[$Path] = $result
    return $result
}

# Издатели, чьи DLL внутри игры - обычное дело: оверлеи, драйверы,
# периферия, сам Steam. Сверка идёт по подстроке в имени из сертификата.
$script:TrustedSigners = @(
    'Valve', 'Microsoft', 'NVIDIA', 'Advanced Micro Devices', 'ATI Technologies',
    'Intel', 'Google', 'Discord', 'Overwolf', 'Logitech', 'Logi', 'Razer',
    'Corsair', 'SteelSeries', 'ASUSTeK', 'Micro-Star', 'Giga-Byte', 'Realtek',
    'Creative Technology', 'Epic Games', 'Electronic Arts', 'Unwinder',
    'Guru3D', 'OBS', 'Mozilla', 'Oracle', 'Dell', 'Hewlett', 'Lenovo',
    'Apple', 'Western Digital', 'Nahimic', 'A-Volute', 'SteelSeries',
    'TeamSpeak', 'Riot Games', 'Ubisoft', 'Wacom', 'Elgato'
)

function Test-TrustedSigner {
    param([string] $SigInfo)
    if (-not (Test-SigOk $SigInfo)) { return $false }
    foreach ($t in $script:TrustedSigners) {
        if ($SigInfo.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

function Test-SigOk {
    param([string] $SigInfo)
    return ($SigInfo -like 'Valid:*')
}

# Папки, из которых нормальная игровая DLL грузиться не должна.
# Шаблоны для -like, с одинарными слэшами - без regex, чтобы не путаться с экранированием.
$script:SuspectDirPatterns = @(
    '*\AppData\Local\Temp\*', '*\Windows\Temp\*', '*\Downloads\*',
    '*\Desktop\*', '*\Documents\*', '*\AppData\Roaming\*',
    '*\ProgramData\*', '*\Users\Public\*', '*\$Recycle.Bin\*'
)

function Test-SuspectPath {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    foreach ($p in $script:SuspectDirPatterns) {
        if ($Path -like $p) { return $true }
    }
    return $false
}

# Поведенческие паттерны в именах файлов. Намеренно общие: конкретные названия
# читов меняются каждую неделю, а слова «инжектор» и «загрузчик» - нет.
# Короткие слова вроде esp/kdu намеренно привязаны к границам, иначе они
# ловят половину системных файлов («Response», «dsetup» и прочее).
$script:ToolNamePatterns = @(
    'inject', 'loader', 'kdmapper', 'drvmap', 'cheat', 'hack',
    'aimbot', 'triggerbot', 'wallhack', 'spoof', 'hwid',
    'bypass', 'dumper', 'cheatengine', 'extreme.?injector', 'xenos',
    'processhacker', 'patchguard', 'unlocker',
    '(^|[\W_])esp([\W_]|$)', '(^|[\W_])kdu([\W_]|$)',
    '(^|[\W_])dse([\W_]|$)', '(^|[\W_])mapper([\W_]|$)',
    '(^|[\W_])gdrv([\W_]|$)'
)

$script:CleanerNamePatterns = @(
    'ccleaner', 'bleachbit', 'privazer', 'wise.?disk', 'wise.?care',
    'cleaner', 'wiper', 'eraser', 'sdelete', 'shredder', 'timestomp',
    'anti.?forensic', 'nomoretrace', 'clearlog', 'logkill', 'tracecleaner'
)

function Test-NamePattern {
    param([string] $Name, [string[]] $Patterns)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $n = $Name.ToLowerInvariant()
    foreach ($p in $Patterns) { if ($n -match $p) { return $p } }
    return $null
}

# --- Список запрещённого ПО из blocklist.txt --------------------------------
# Держим его отдельным файлом: имена читов меняются каждую неделю, и правка
# списка не должна требовать правки скрипта.

$script:Block = @{ Strict = @(); Loose = @(); Ext = @(); Size = @(); Allow = @() }

function Import-BlockList {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $section = ''
    foreach ($line in (Get-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction SilentlyContinue)) {
        $t = $line.Trim()
        if ($t -match '^\[(\w+)\]') { $section = $Matches[1].ToLowerInvariant(); continue }
        $t = ($t -split '#', 2)[0].Trim()     # срезаем комментарий, в том числе на всю строку
        if (-not $t) { continue }
        switch ($section) {
            'allow'  { $script:Block.Allow  += $t.ToLowerInvariant() }
            'strict' { $script:Block.Strict += $t.ToLowerInvariant() }
            'loose'  { $script:Block.Loose  += $t.ToLowerInvariant() }
            'ext'    { $script:Block.Ext    += $t.ToLowerInvariant() }
            'size'   { $num = 0; if ([int]::TryParse($t, [ref]$num)) { $script:Block.Size += $num } }
        }
    }
}

function Test-Allowed {
    param([string] $Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $n = $Text.ToLowerInvariant()
    foreach ($a in $script:Block.Allow) {
        if ($n.Contains($a)) { return $true }
    }
    return $false
}

# Один вердикт на все места, где проверяется имя файла или программы.
# Порядок важен: точные имена перевешивают общие шаблоны.
function Get-NameVerdict {
    param([string] $Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $n = $Text.ToLowerInvariant()

    foreach ($e in $script:Block.Strict) {
        if ($n.Contains($e)) {
            return [pscustomobject]@{ Severity='High'; Kind='Список запрещённого'; Match=$e }
        }
    }
    # Белый список идёт ПОСЛЕ точных имён: иначе чит можно было бы спрятать,
    # назвав его "anticheat-что-нибудь".
    if (Test-Allowed $n) { return $null }

    foreach ($p in $script:ToolNamePatterns) {
        if ($n -match $p) {
            return [pscustomobject]@{ Severity='High'; Kind='Шаблон инструментария'; Match=$p }
        }
    }
    # Короткие имена ищем только как отдельное слово, иначе «r8» или «maze»
    # поймают половину системных файлов.
    foreach ($e in $script:Block.Loose) {
        if ($n -match ('(^|[\W_])' + [regex]::Escape($e) + '([\W_]|$)')) {
            return [pscustomobject]@{ Severity='Medium'; Kind='Спорное имя из списка'; Match=$e }
        }
    }
    foreach ($e in $script:Block.Ext) {
        if ($n.EndsWith($e)) {
            return [pscustomobject]@{ Severity='Medium'; Kind='Расширение из списка'; Match=$e }
        }
    }
    foreach ($p in $script:CleanerNamePatterns) {
        if ($n -match $p) {
            return [pscustomobject]@{ Severity='Medium'; Kind='Чистильщик следов'; Match=$p }
        }
    }
    return $null
}

# Драйверы, которыми пользуются для загрузки неподписанного кода в ядро (BYOVD).
# Это лишь затравка - полный список берите с loldrivers.io и обновляйте.
$script:KnownAbusedDrivers = @{
    'iqvw64e.sys'      = 'Intel NIC - классический драйвер для kdmapper'
    'iqvw32.sys'       = 'Intel NIC (32-бит)'
    'dbutil_2_3.sys'   = 'Dell BIOS Utility - известная BYOVD-уязвимость'
    'dbutildrv2.sys'   = 'Dell BIOS Utility'
    'gdrv.sys'         = 'Gigabyte - произвольная запись в память'
    'gdrv2.sys'        = 'Gigabyte'
    'winring0x64.sys'  = 'WinRing0 - часто идёт с легальным софтом, но и абьюзится'
    'winio.sys'        = 'WinIo - прямой доступ к портам/памяти'
    'inpoutx64.sys'    = 'InpOut32/64 - прямой доступ к портам'
    'asio.sys'         = 'ASUS AsIO'
    'asio2.sys'        = 'ASUS AsIO2'
    'asio3.sys'        = 'ASUS AsIO3'
    'rtcore64.sys'     = 'MSI Afterburner / RivaTuner - легален, но известен как BYOVD'
    'ene.sys'          = 'ENE Technology'
    'enetechio64.sys'  = 'ENE Technology'
    'mhyprot2.sys'     = 'Genshin Impact anti-cheat - абьюзится как BYOVD'
    'mhyprot3.sys'     = 'Genshin Impact anti-cheat'
    'echo_driver.sys'  = 'Echo AC - известная уязвимость'
    'amifldrv64.sys'   = 'AMI Firmware Update'
    'atillk64.sys'     = 'ATI/AMD diagnostics'
    'glckio2.sys'      = 'ASUS GLCKIO2'
    'ntiolib_x64.sys'  = 'MSI NTIOLib'
    'speedfan.sys'     = 'SpeedFan'
    'truesight.sys'    = 'Adlice TrueSight - абьюзится'
    'viragt64.sys'     = 'VirIT Agent'
    'segwindrvx64.sys' = 'Phoenix/Insyde'
    'physmem.sys'      = 'Прямой доступ к физической памяти'
    'kdu.sys'          = 'Kernel Driver Utility'
}

# ============================================================================
#  ЭКРАН СОГЛАСИЯ
# ============================================================================

function Show-Consent {
    Clear-Host
    Write-Host ''
    Write-Host '  ================================================================' -ForegroundColor Cyan
    Write-Host '   CS2Check - проверка компьютера на следы читов' -ForegroundColor Cyan
    Write-Host ('   версия ' + $script:ScriptVersion) -ForegroundColor DarkCyan
    Write-Host '  ================================================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  ЧТО СКРИПТ СОБИРАЕТ:' -ForegroundColor White
    Write-Host '   - список запущенных процессов, их пути и цифровые подписи'
    Write-Host '   - список DLL, загруженных в процесс игры cs2.exe'
    Write-Host '   - историю запуска программ (Prefetch, BAM, UserAssist, MUICache)'
    Write-Host '   - список загруженных драйверов и состояние Secure Boot'
    Write-Host '   - записи об удалённых .exe/.dll/.sys из журнала файловой системы'
    Write-Host '   - имена файлов в папках Загрузки / Temp / Недавние'
    Write-Host '   - параметры запуска Steam и целостность файлов CS2'
    Write-Host '   - модель ПК, время работы системы, подключённые PCI-устройства'
    Write-Host ''
    Write-Host '  ЧТО СКРИПТ НЕ ДЕЛАЕТ:' -ForegroundColor White
    Write-Host '   - не читает содержимое ваших файлов, документов и переписок'
    Write-Host '   - не собирает пароли, куки, историю браузера и скриншоты'
    Write-Host '   - не меняет настройки, не ставит драйверы, не прописывается в автозапуск'
    Write-Host '   - не отправляет ничего, пока вы не увидите отчёт своими глазами'
    Write-Host ''
    Write-Host '  Отчёт будет сохранён на ваш Рабочий стол. Вы сможете открыть его' -ForegroundColor Yellow
    Write-Host '  и прочитать ПЕРЕД тем, как передавать администратору.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Код скрипта открыт - откройте CS2Check.ps1 блокнотом и проверьте сами.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  ----------------------------------------------------------------'
    Write-Host '  Напишите СОГЛАСЕН и нажмите Enter, чтобы начать.' -ForegroundColor Green
    Write-Host '  Любой другой ввод закроет программу без сбора данных.'
    Write-Host ''
    $answer = Read-Host '  Ваш ответ'
    return ($answer.Trim().ToUpperInvariant() -in @('СОГЛАСЕН','СОГЛАСНА','ДА','AGREE','YES'))
}

# ============================================================================
#  СБОР: СИСТЕМА
# ============================================================================

function Collect-System {
    Write-Step 'Система, время работы, Secure Boot'
    $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs  = Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue
    $bios= Get-CimInstance Win32_BIOS            -ErrorAction SilentlyContinue

    $bootTime = $null; $uptimeMin = $null
    if ($os) {
        $bootTime  = $os.LastBootUpTime
        $uptimeMin = [math]::Round(((Get-Date) - $bootTime).TotalMinutes, 1)
    }

    $secureBoot = 'Unknown'
    try { $secureBoot = [string](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBoot = 'N/A (Legacy BIOS или нет прав)' }

    # bcdedit: testsigning / nointegritychecks отключают проверку подписи драйверов
    $bcd = ''
    try { $bcd = (bcdedit /enum '{current}' 2>&1 | Out-String) } catch {}
    $testSigning = ($bcd -match '(?im)^\s*testsigning\s+Yes')
    $noIntegrity = ($bcd -match '(?im)^\s*nointegritychecks\s+Yes')
    $kernelDebug = ($bcd -match '(?im)^\s*debug\s+Yes')

    $hvci = 'Unknown'
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
              -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        $hvci = if ($dg.SecurityServicesRunning -contains 2) { 'Enabled' } else { 'Disabled' }
    } catch {}

    # PowerShell 5.1 не принимает конструкцию if/else прямо внутри литерала
    # хэш-таблицы, поэтому все значения считаем заранее.
    $osText   = 'Unknown'
    if ($os) { $osText = [string]$os.Caption + ' build ' + [string]$os.BuildNumber }
    $vendor   = ''
    $model    = ''
    $biosVer  = ''
    if ($cs)   { $vendor  = [string]$cs.Manufacturer; $model = [string]$cs.Model }
    if ($bios) { $biosVer = [string]$bios.SMBIOSBIOSVersion }
    $tzId = ''
    try { $tzId = (Get-TimeZone -ErrorAction Stop).Id } catch {}

    $script:Data['System'] = [ordered]@{
        ComputerName   = $env:COMPUTERNAME
        UserName       = $env:USERNAME
        OS             = $osText
        Manufacturer   = $vendor
        Model          = $model
        BiosVersion    = $biosVer
        LastBootUpTime = $bootTime
        UptimeMinutes  = $uptimeMin
        LocalTime      = (Get-Date).ToString('o')
        TimeZone       = $tzId
        SecureBoot     = $secureBoot
        HVCI           = $hvci
        TestSigning    = $testSigning
        NoIntegrity    = $noIntegrity
        KernelDebug    = $kernelDebug
    }

    # --- правила ---
    if ($uptimeMin -ne $null -and $uptimeMin -lt 20) {
        Add-Finding High 'Система' 'Компьютер перезагружался незадолго до проверки' `
            ("Система работает всего $uptimeMin мин. Перезагрузка стирает список процессов, " +
             "загруженные модули и выгружает драйверы - то есть именно те следы, которые " +
             "проверка ищет в первую очередь. Проверять ПК после ребута почти бессмысленно.") `
            @{ LastBoot = $bootTime; UptimeMinutes = $uptimeMin }
    }
    if ($testSigning) {
        Add-Finding High 'Ядро' 'Включён режим Test Signing' `
            'В этом режиме Windows грузит драйверы без действительной цифровой подписи. Для обычной игры не нужен никогда.'
    }
    if ($noIntegrity) {
        Add-Finding High 'Ядро' 'Отключена проверка целостности драйверов (nointegritychecks)' `
            'Прямой способ загрузить самописный драйвер. Легальных бытовых причин практически нет.'
    }
    if ($kernelDebug) {
        Add-Finding Medium 'Ядро' 'Включена отладка ядра (debug=Yes)' `
            'Используется разработчиками, но также позволяет вмешиваться в работу ядра. Уточните у игрока причину.'
    }
    if ($secureBoot -eq 'False') {
        Add-Finding Low 'Ядро' 'Secure Boot отключён' `
            'Само по себе встречается часто и ни о чём не говорит, но в сочетании с другими флагами усиливает их.'
    }

    # Виртуальная машина: игра в ВМ может означать чит на хост-системе
    $vmHints = @('VMware','VirtualBox','VBOX','QEMU','KVM','Virtual Machine','Xen','Parallels','Hyper-V')
    $modelStr = (([string]$cs.Manufacturer) + ' ' + ([string]$cs.Model) + ' ' + ([string]$bios.SMBIOSBIOSVersion))
    foreach ($h in $vmHints) {
        if ($modelStr -like ('*' + $h + '*')) {
            Add-Finding High 'Система' 'Похоже на виртуальную машину' `
                ("Признак: '$h' в сведениях о железе. Игра внутри ВМ позволяет держать чит на " +
                 "хост-системе, куда проверка не достаёт.") @{ Hardware = $modelStr }
            break
        }
    }
}

# ============================================================================
#  СБОР: ПРОЦЕССЫ
# ============================================================================

function Collect-Processes {
    Write-Step 'Процессы: пути, подписи, командные строки'
    $cim = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $cim[[int]$_.ProcessId] = $_
    }

    $list = New-Object System.Collections.ArrayList
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        $path = $null
        try { $path = $p.MainModule.FileName } catch {}
        $w = $cim[[int]$p.Id]
        if (-not $path -and $w) { $path = $w.ExecutablePath }

        $sig = Get-SigInfo $path
        $start = $null
        try { $start = $p.StartTime } catch {}

        $cmdLine = $null
        if ($w) { $cmdLine = $w.CommandLine }
        $exists = $false
        if ($path) { $exists = Test-Path -LiteralPath $path }

        [void]$list.Add([pscustomobject]@{
            Pid         = $p.Id
            Name        = $p.ProcessName
            Path        = $path
            Signature   = $sig
            CommandLine = $cmdLine
            StartTime   = $start
            FileExists  = $exists
        })
    }
    $script:Data['Processes'] = $list

    foreach ($proc in $list) {
        # 1. Процесс есть, а файла на диске нет - файл удалили, пока он работает.
        if ($proc.Path -and -not $proc.FileExists) {
            Add-Finding High 'Процессы' ('Процесс работает, но его файл удалён: ' + $proc.Name) `
                'Классическая картина: программу запустили, затем удалили файл, чтобы не осталось следов. Процесс при этом продолжает жить в памяти.' `
                $proc
        }
        # 2. Имя намекает на инструментарий для инжекта/маппинга.
        $v = Get-NameVerdict $proc.Name
        if (-not $v -and $proc.Path) { $v = Get-NameVerdict $proc.Path }
        if ($v) {
            Add-Finding $v.Severity 'Процессы' ('Подозрительное имя процесса: ' + $proc.Name) `
                ($v.Kind + ", совпадение '" + $v.Match + "'. Путь: " + $proc.Path) $proc
        }
        # 3. Неподписанный процесс из временной/пользовательской папки.
        if ($proc.Path -and (Test-SuspectPath $proc.Path) -and -not (Test-TrustedSigner $proc.Signature) `
            -and -not (Test-SigOk $proc.Signature)) {
            Add-Finding Medium 'Процессы' ('Неподписанная программа из нестандартной папки: ' + $proc.Name) `
                ('Путь: ' + $proc.Path + ' | Подпись: ' + $proc.Signature) $proc
        }
    }
}

# ============================================================================
#  СБОР: МОДУЛИ CS2
# ============================================================================

function Collect-Cs2Modules {
    Write-Step 'Модули, загруженные в cs2.exe'
    $cs2 = Get-Process -Name 'cs2' -ErrorAction SilentlyContinue
    if (-not $cs2) {
        $script:Data['Cs2Modules'] = @()
        Add-Finding Medium 'Игра' 'CS2 не запущена во время проверки' `
            ('Самый ценный артефакт - список DLL внутри cs2.exe - собрать невозможно. ' +
             'Проверку нужно проводить, не закрывая игру.')
        return
    }

    $gameDir = ''
    try { $gameDir = Split-Path $cs2.MainModule.FileName -Parent } catch {}
    $modules = New-Object System.Collections.ArrayList

    try {
        foreach ($m in $cs2.Modules) {
            $sig = Get-SigInfo $m.FileName
            [void]$modules.Add([pscustomobject]@{
                Name       = $m.ModuleName
                Path       = $m.FileName
                Signature  = $sig
                FileExists = Test-Path -LiteralPath $m.FileName
                BaseAddress= ('0x{0:X}' -f [int64]$m.BaseAddress)
            })
        }
    } catch {
        Add-Finding Medium 'Игра' 'Не удалось прочитать список модулей cs2.exe' `
            ('Ошибка: ' + $_.Exception.Message + '. Запустите скрипт от имени администратора.')
    }
    $script:Data['Cs2Modules'] = $modules

    # Нормальные источники DLL для игры. Строим из переменных окружения и
    # сравниваем через -like: в -match скобки в "Program Files (x86)" читаются
    # как группа регулярного выражения, и путь перестаёт совпадать.
    $okPaths = @('*\steamapps\*')
    foreach ($base in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($base) { $okPaths += (Join-Path $base '*') }
    }
    if ($gameDir) { $okPaths += ($gameDir + '*') }
    foreach ($m in $modules) {
        $v = Get-NameVerdict $m.Name
        if (-not $v) { $v = Get-NameVerdict $m.Path }
        if ($v) {
            Add-Finding High 'Игра' ('Модуль из списка запрещённого внутри cs2.exe: ' + $m.Name) `
                ($v.Kind + ", совпадение '" + $v.Match + "'. Путь: " + $m.Path +
                 '. Это самое весомое, что может найти проверка.') $m
        }

        $inOkPath = $false
        foreach ($r in $okPaths) { if ($m.Path -like $r) { $inOkPath = $true; break } }

        if (-not $m.FileExists) {
            Add-Finding High 'Игра' ('В игру загружен модуль, которого нет на диске: ' + $m.Name) `
                ('Путь: ' + $m.Path + '. Файл удалили после инжекта - очень характерный признак.') $m
        }
        elseif (Test-TrustedSigner $m.Signature) {
            # Valve, драйверы, оверлеи известных производителей. Молчим.
        }
        elseif (Test-SuspectPath $m.Path) {
            Add-Finding High 'Игра' ('Модуль из временной папки внутри cs2.exe: ' + $m.Name) `
                ('Путь: ' + $m.Path + ' | Подпись: ' + $m.Signature +
                 '. DLL из Temp, Downloads или Desktop не попадает в процесс игры сама по себе.') $m
        }
        elseif (-not (Test-SigOk $m.Signature)) {
            Add-Finding Medium 'Игра' ('Неподписанный модуль в cs2.exe: ' + $m.Name) `
                ('Путь: ' + $m.Path + ' | Подпись: ' + $m.Signature +
                 '. Так же выглядят оверлеи и мониторинг - сверьтесь с тем, что стоит у игрока.') $m
        }
        elseif (-not $inOkPath) {
            Add-Finding Medium 'Игра' ('Подписанный, но посторонний модуль в cs2.exe: ' + $m.Name) `
                ('Путь: ' + $m.Path + ' | Подпись: ' + $m.Signature +
                 '. Подпись действительна, но издатель незнакомый, а папка нетипичная.') $m
        }
    }
}

# ============================================================================
#  СБОР: ИСТОРИЯ ЗАПУСКОВ
# ============================================================================

function Collect-Prefetch {
    Write-Step 'Prefetch - история запуска программ'
    $dir = Join-Path $env:SystemRoot 'Prefetch'
    $enabled = $null
    try {
        $enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' `
                    -Name 'EnablePrefetcher' -ErrorAction Stop).EnablePrefetcher
    } catch {}

    $files = @()
    if (Test-Path $dir) {
        $files = Get-ChildItem -Path $dir -Filter '*.pf' -ErrorAction SilentlyContinue |
                 Select-Object Name, CreationTime, LastWriteTime, Length |
                 Sort-Object LastWriteTime -Descending
    }
    $script:Data['Prefetch'] = [ordered]@{
        EnablePrefetcher = $enabled
        Count            = $files.Count
        Entries          = $files
    }

    if ($enabled -eq 0) {
        Add-Finding High 'История запусков' 'Prefetch отключён в реестре' `
            ('EnablePrefetcher = 0. Это ручное изменение: именно так прячут историю запуска программ. ' +
             'На обычной игровой машине Prefetch включён.')
    }
    if ($files.Count -lt 30 -and $enabled -ne 0) {
        Add-Finding High 'История запусков' ('В Prefetch всего ' + $files.Count + ' записей') `
            ('На живой системе их обычно сотни. Малое число означает, что папку недавно очистили ' +
             'или систему только что поставили.')
    }

    foreach ($f in $files) {
        $v = Get-NameVerdict $f.Name
        if ($v) {
            Add-Finding $v.Severity 'История запусков' ('Prefetch: запускалось ' + $f.Name) `
                ($v.Kind + ", совпадение '" + $v.Match + "'. Последний запуск: " + $f.LastWriteTime +
                 '. Запись остаётся, даже если сам файл удалён. Сравните время с моментом, ' +
                 'когда вы попросили игрока пройти проверку.') $f
        }
    }
}

function Collect-Bam {
    Write-Step 'BAM - время последнего запуска программ'
    $roots = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
    )
    $entries = New-Object System.Collections.ArrayList
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($sidKey in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $key = $null
            try { $key = Get-Item $sidKey.PSPath -ErrorAction Stop } catch { continue }
            foreach ($name in $key.GetValueNames()) {
                if ($name -eq 'Version' -or $name -eq 'SequenceNumber') { continue }
                $val = $key.GetValue($name)
                $when = $null
                if ($val -is [byte[]] -and $val.Length -ge 8) {
                    try { $when = [DateTime]::FromFileTime([BitConverter]::ToInt64($val,0)) } catch {}
                }
                [void]$entries.Add([pscustomobject]@{
                    Sid      = $sidKey.PSChildName
                    Path     = $name
                    LastRun  = $when
                })
            }
        }
    }
    $script:Data['Bam'] = ($entries | Sort-Object LastRun -Descending)

    foreach ($e in $entries) {
        $leaf = ''
        try { $leaf = Split-Path $e.Path -Leaf } catch { $leaf = $e.Path }
        $v = Get-NameVerdict $leaf
        if (-not $v) { $v = Get-NameVerdict $e.Path }
        if ($v) {
            Add-Finding $v.Severity 'История запусков' ('BAM: запускалось ' + $leaf) `
                ($v.Kind + ", совпадение '" + $v.Match + "'. Последний запуск: " + $e.LastRun +
                 ' | Путь: ' + $e.Path + '. BAM чистят редко - это надёжный артефакт.') $e
        }
    }
}

function Convert-Rot13 {
    param([string] $Text)
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $Text.ToCharArray()) {
        $i = [int]$c
        if     ($i -ge 97 -and $i -le 122) { [void]$sb.Append([char]((($i - 97 + 13) % 26) + 97)) }
        elseif ($i -ge 65 -and $i -le 90)  { [void]$sb.Append([char]((($i - 65 + 13) % 26) + 65)) }
        else                               { [void]$sb.Append($c) }
    }
    $sb.ToString()
}

function Collect-UserAssist {
    Write-Step 'UserAssist и MUICache - что пользователь открывал'
    $entries = New-Object System.Collections.ArrayList
    $base = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    if (Test-Path $base) {
        foreach ($guid in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
            $countKey = Join-Path $guid.PSPath 'Count'
            if (-not (Test-Path $countKey)) { continue }
            $k = $null
            try { $k = Get-Item $countKey -ErrorAction Stop } catch { continue }
            foreach ($name in $k.GetValueNames()) {
                $decoded = Convert-Rot13 $name
                $raw = $k.GetValue($name)
                $runs = $null; $last = $null
                if ($raw -is [byte[]] -and $raw.Length -ge 68) {
                    try {
                        $runs = [BitConverter]::ToInt32($raw, 4)
                        $ft   = [BitConverter]::ToInt64($raw, 60)
                        if ($ft -gt 0) { $last = [DateTime]::FromFileTime($ft) }
                    } catch {}
                }
                [void]$entries.Add([pscustomobject]@{
                    Name = $decoded; RunCount = $runs; LastRun = $last
                })
            }
        }
    }
    $script:Data['UserAssist'] = ($entries | Sort-Object LastRun -Descending)

    foreach ($e in $entries) {
        $v = Get-NameVerdict $e.Name
        if ($v) {
            Add-Finding $v.Severity 'История запусков' ('UserAssist: открывалось ' + (Split-Path $e.Name -Leaf)) `
                ($v.Kind + ", совпадение '" + $v.Match + "'. Запусков: " + $e.RunCount +
                 ' | Последний: ' + $e.LastRun + ' | Полный путь: ' + $e.Name) $e
        }
    }

    # MUICache - имена программ, когда-либо запускавшихся через Explorer
    $mui = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
    $muiList = New-Object System.Collections.ArrayList
    if (Test-Path $mui) {
        $k = Get-Item $mui -ErrorAction SilentlyContinue
        if ($k) {
            foreach ($name in $k.GetValueNames()) {
                [void]$muiList.Add([pscustomobject]@{ Path = $name; FriendlyName = [string]$k.GetValue($name) })
                # У одной программы в MUICache два значения:
                # <путь>.FriendlyAppName и <путь>.ApplicationCompany.
                $muiTarget = $name -replace '\.(FriendlyAppName|ApplicationCompany)$', ''
                $leafName  = $muiTarget
                try { $leafName = Split-Path $muiTarget -Leaf } catch {}
                $v = Get-NameVerdict $muiTarget
                if ($v) {
                    Add-Finding Medium 'История запусков' ('MUICache: ' + $leafName) `
                        ($v.Kind + ", совпадение '" + $v.Match + "'. Путь: " + $muiTarget)
                }
            }
        }
    }
    $script:Data['MuiCache'] = $muiList
}

function Collect-RecentFiles {
    Write-Step 'Загрузки, Temp, Недавние документы'
    $targets = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        $env:TEMP,
        (Join-Path $env:APPDATA 'Microsoft\Windows\Recent'),
        (Join-Path $env:USERPROFILE 'Desktop')
    )
    $interesting = @('.exe','.dll','.sys','.rar','.zip','.7z','.bat','.ps1','.lnk') +
                   $script:Block.Ext
    $found = New-Object System.Collections.ArrayList

    foreach ($t in $targets) {
        if (-not $t -or -not (Test-Path $t)) { continue }
        $items = Get-ChildItem -LiteralPath $t -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
                 Where-Object { $interesting -contains $_.Extension.ToLowerInvariant() } |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 300
        foreach ($i in $items) {
            [void]$found.Add([pscustomobject]@{
                Folder       = $t
                Name         = $i.Name
                FullPath     = $i.FullName
                SizeKB       = [math]::Round($i.Length / 1KB, 1)
                CreationTime = $i.CreationTime
                LastWrite    = $i.LastWriteTime
            })
            $v = Get-NameVerdict $i.Name
            if ($v) {
                Add-Finding $v.Severity 'Файлы' ('Подозрительный файл: ' + $i.Name) `
                    ($v.Kind + ", совпадение '" + $v.Match + "'. Путь: " + $i.FullName +
                     ' | Создан: ' + $i.CreationTime)
            }
            # Размер ловит переименованное: имя файла меняют за секунду,
            # а пересобирают сборку редко.
            $kb = [int][math]::Round($i.Length / 1KB)
            if ($script:Block.Size -contains $kb) {
                Add-Finding High 'Файлы' ('Совпадение по размеру: ' + $i.Name) `
                    ([string]$kb + ' КБ есть в списке запрещённого. Путь: ' + $i.FullName +
                     '. Имя при этом может быть любым.')
            }
            # Timestomp: у подделанных дат обнуляются секунды и миллисекунды.
            if ($i.LastWriteTime.Second -eq 0 -and $i.LastWriteTime.Millisecond -eq 0 -and
                $i.Extension.ToLowerInvariant() -in @('.exe','.dll','.sys')) {
                Add-Finding Low 'Антифорензика' ('Возможно подделана дата файла: ' + $i.Name) `
                    ('LastWriteTime = ' + $i.LastWriteTime.ToString('o') +
                     '. Ровные секунды и миллисекунды бывают у файлов с переписанными датами, но встречаются и естественно.')
            }
        }
    }
    $script:Data['RecentFiles'] = $found
}

# ============================================================================
#  СБОР: СЛЕДЫ УДАЛЕНИЯ
# ============================================================================

function Collect-UsnJournal {
    if ($SkipUsn) { $script:Data['Usn'] = @{ Skipped = $true }; return }
    Write-Step 'USN-журнал - следы удалённых .exe/.dll/.sys (может занять минуту)'

    # Ориентируемся на код возврата fsutil, а не на текст: сообщения
    # переведены и на русской Windows выглядят иначе, чем на английской.
    $query = ''
    $journalPresent = $false
    try {
        $global:LASTEXITCODE = 0
        $query = (fsutil usn queryjournal C: 2>&1 | Out-String)
        $journalPresent = ($LASTEXITCODE -eq 0)
    } catch { $journalPresent = $false }

    if (-not $journalPresent) {
        Add-Finding High 'Антифорензика' 'USN-журнал файловой системы отсутствует или был удалён' `
            ('Журнал NTFS включён по умолчанию и фиксирует все изменения файлов. Его удаляют ' +
             'командой fsutil usn deletejournal - ровно для того, чтобы скрыть, какие файлы были стёрты.') `
            @{ Raw = $query.Trim() }
        $script:Data['Usn'] = [ordered]@{ Present = $false; Raw = $query.Trim() }
        return
    }

    # Формат CSV у fsutil зависит от версии и локали Windows, а названия причин
    # («File delete») переводятся. Поэтому фильтруем по расширению и сохраняем
    # сырые строки - админ разберёт их глазами.
    $hits = New-Object System.Collections.ArrayList
    try {
        $job = Start-Job -ScriptBlock { fsutil usn readjournal C: csv 2>&1 }
        if (Wait-Job $job -Timeout 180) {
            $lines = Receive-Job $job
            foreach ($line in $lines) {
                $s = [string]$line
                if ($s -match '(?i)\.(exe|dll|sys)\b') {
                    $name = ''
                    $m = [regex]::Match($s, '(?i)([^\\,"\s]+\.(exe|dll|sys))')
                    if ($m.Success) { $name = $m.Groups[1].Value }
                    [void]$hits.Add([pscustomobject]@{ FileName = $name; Raw = $s })
                    if ($hits.Count -ge 4000) { break }
                }
            }
        } else {
            Add-Finding Low 'Антифорензика' 'Чтение USN-журнала не успело завершиться' `
                'Диск большой или нагружен. Запустите скрипт снова или соберите журнал вручную.'
        }
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    } catch {
        Add-Finding Low 'Антифорензика' 'Не удалось прочитать USN-журнал' ('Ошибка: ' + $_.Exception.Message)
    }

    $script:Data['Usn'] = [ordered]@{
        Present = $true
        Header  = $query.Trim()
        Hits    = $hits
    }

    foreach ($h in $hits) {
        $v = Get-NameVerdict $h.FileName
        # Имя в журнале обрезается по пробелу, поэтому программа из белого
        # списка теряет начало. Сверяем строку целиком.
        if ($v -and (Test-Allowed $h.Raw)) { $v = $null }
        if ($v) {
            Add-Finding $v.Severity 'Антифорензика' ('USN: в журнале есть ' + $h.FileName) `
                ($v.Kind + ", совпадение '" + $v.Match +
                 "'. Журнал фиксирует файл, даже если он уже удалён с диска.") $h
        }
    }
    # Много .sys в журнале - возможный след ручной загрузки драйверов.
    $sysCount = @($hits | Where-Object { $_.FileName -like '*.sys' }).Count
    if ($sysCount -gt 0) {
        Add-Finding Info 'Антифорензика' ('В USN-журнале ' + $sysCount + ' записей о .sys-файлах') `
            'Просмотрите список вручную: появление и исчезновение .sys вне обновлений Windows - след загрузки драйвера.'
    }
}

function Collect-EventLogs {
    Write-Step 'Журналы событий - факты очистки'
    $cleared = New-Object System.Collections.ArrayList
    foreach ($spec in @(@{Log='Security'; Id=1102}, @{Log='System'; Id=104})) {
        try {
            $ev = Get-WinEvent -FilterHashtable @{ LogName = $spec.Log; Id = $spec.Id } `
                  -MaxEvents 20 -ErrorAction Stop
            foreach ($e in $ev) {
                [void]$cleared.Add([pscustomobject]@{
                    Log = $spec.Log; Id = $spec.Id; Time = $e.TimeCreated
                })
                Add-Finding High 'Антифорензика' ('Журнал событий ' + $spec.Log + ' был очищен') `
                    ('Время очистки: ' + $e.TimeCreated + '. Сверьте с моментом, когда вы попросили игрока пройти проверку.')
            }
        } catch {}
    }
    $script:Data['LogClears'] = $cleared

    # Корзина: пусто при наличии других следов удаления - тоже сигнал
    $rb = 'C:\$Recycle.Bin'
    $rbCount = 0
    if (Test-Path $rb) {
        $rbCount = (Get-ChildItem $rb -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object).Count
    }
    $script:Data['RecycleBinItems'] = $rbCount
}

# ============================================================================
#  СБОР: ДРАЙВЕРЫ И УСТРОЙСТВА
# ============================================================================

function Collect-Drivers {
    Write-Step 'Драйверы и состояние ядра'
    $list = New-Object System.Collections.ArrayList
    foreach ($d in (Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        $path = $d.PathName
        if ($path) { $path = $path -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', ($env:SystemRoot + '\') }
        $leaf = ''
        if ($path) { try { $leaf = (Split-Path $path -Leaf).ToLowerInvariant() } catch {} }

        # Подпись проверяем только у работающих - иначе скрипт тормозит на
        # сотнях остановленных драйверов, которые нас не интересуют.
        $drvSig = 'NotChecked'
        if ($d.State -eq 'Running') { $drvSig = Get-SigInfo $path }

        $row = [pscustomobject]@{
            Name        = $d.Name
            DisplayName = $d.DisplayName
            State       = $d.State
            StartMode   = $d.StartMode
            Path        = $path
            FileName    = $leaf
            Signature   = $drvSig
        }
        [void]$list.Add($row)

        if ($leaf -and $script:KnownAbusedDrivers.ContainsKey($leaf)) {
            $drvSev = 'Medium'
            if ($d.State -eq 'Running') { $drvSev = 'High' }
            Add-Finding $drvSev 'Ядро' ('Уязвимый драйвер: ' + $leaf) `
                ($script:KnownAbusedDrivers[$leaf] + ' | Состояние: ' + $d.State +
                 '. Такие драйверы используют, чтобы загрузить неподписанный код в ядро. ' +
                 'Часть из них приходит с легальным софтом - выясните, какая программа его поставила.') $row
        }
        if ($d.State -eq 'Running' -and $path -and (Test-SuspectPath $path)) {
            Add-Finding High 'Ядро' ('Работающий драйвер из нестандартной папки: ' + $leaf) `
                ('Путь: ' + $path + '. Системные драйверы живут в \Windows\System32\drivers.') $row
        }
    }
    $script:Data['Drivers'] = $list

    # PCI / Thunderbolt устройства - для поиска DMA-карт
    $devs = @()
    try {
        $devs = Get-PnpDevice -ErrorAction Stop |
                Where-Object { $_.Status -eq 'OK' -and $_.Class -in @('System','Net','SCSIAdapter','USB','Unknown','MEDIA') } |
                Select-Object Class, FriendlyName, InstanceId |
                Sort-Object Class, FriendlyName
    } catch {}
    $script:Data['PnpDevices'] = $devs

    foreach ($dv in $devs) {
        if ($dv.FriendlyName -match '(?i)DMA|FPGA|Xilinx|Altera|Lattice|Screamer|LeetDMA|Squirrel|AC701|CaptureCard') {
            Add-Finding High 'Железо' ('Устройство с признаками DMA/FPGA: ' + $dv.FriendlyName) `
                ('InstanceId: ' + $dv.InstanceId + '. PCIe-платы на FPGA читают память игры напрямую, ' +
                 'минуя Windows - обычный чекер их не видит, а имя устройства иногда выдаёт.') $dv
        }
    }
}

# ============================================================================
#  СБОР: STEAM И CS2
# ============================================================================

function Collect-Steam {
    Write-Step 'Steam и файлы CS2'
    $steamPath = $null
    foreach ($k in @('HKCU:\Software\Valve\Steam','HKLM:\SOFTWARE\WOW6432Node\Valve\Steam')) {
        try {
            $v = Get-ItemProperty -Path $k -ErrorAction Stop
            if ($v.SteamPath)     { $steamPath = $v.SteamPath }
            elseif ($v.InstallPath) { $steamPath = $v.InstallPath }
            if ($steamPath) { break }
        } catch {}
    }

    $info = [ordered]@{ SteamPath = $steamPath; Accounts = @(); LaunchOptions = @(); GameFiles = @() }

    if ($steamPath) {
        $steamPath = $steamPath -replace '/','\'

        # Несколько аккаунтов на машине - повод спросить, с каких ещё играли
        $userdata = Join-Path $steamPath 'userdata'
        if (Test-Path $userdata) {
            # Папка "0" в userdata служебная, к реальным аккаунтам не относится.
            $accs = @(Get-ChildItem $userdata -Directory -ErrorAction SilentlyContinue |
                      Select-Object -ExpandProperty Name |
                      Where-Object { $_ -ne '0' -and $_ -ne 'anonymous' })
            $info['Accounts'] = $accs
            if ($accs.Count -gt 1) {
                Add-Finding Low 'Steam' ('На компьютере следы ' + $accs.Count + ' Steam-аккаунтов') `
                    ('ID: ' + ($accs -join ', ') + '. Само по себе нормально (общий ПК, смурф), ' +
                     'но стоит проверить эти ID на VAC-баны.')
            }
            # Параметры запуска: -insecure отключает VAC
            foreach ($acc in $accs) {
                $cfg = Join-Path $userdata (Join-Path $acc 'config\localconfig.vdf')
                if (-not (Test-Path $cfg)) { continue }
                try {
                    $txt = Get-Content -LiteralPath $cfg -Raw -ErrorAction Stop
                    foreach ($m in [regex]::Matches($txt, '(?i)"LaunchOptions"\s*"([^"]*)"')) {
                        $opt = $m.Groups[1].Value
                        if ([string]::IsNullOrWhiteSpace($opt)) { continue }
                        $info['LaunchOptions'] += [pscustomobject]@{ Account = $acc; Options = $opt }
                        if ($opt -match '(?i)-insecure') {
                            Add-Finding High 'Steam' 'В параметрах запуска найден -insecure' `
                                ('Аккаунт ' + $acc + ': "' + $opt + '". Этот флаг запускает игру с отключённым VAC.')
                        }
                    }
                } catch {}
            }
        }

        # Файлы в папке игры: сторонние DLL и правленый gameinfo.gi
        $libs = @((Join-Path $steamPath 'steamapps'))
        $vdf = Join-Path $steamPath 'steamapps\libraryfolders.vdf'
        if (Test-Path $vdf) {
            try {
                $t = Get-Content -LiteralPath $vdf -Raw
                foreach ($m in [regex]::Matches($t, '(?i)"path"\s*"([^"]+)"')) {
                    $libs += (Join-Path ($m.Groups[1].Value -replace '\\\\','\') 'steamapps')
                }
            } catch {}
        }
        foreach ($lib in ($libs | Select-Object -Unique)) {
            $gameRoot = Join-Path $lib 'common\Counter-Strike Global Offensive'
            if (-not (Test-Path $gameRoot)) { continue }

            $gi = Join-Path $gameRoot 'game\csgo\gameinfo.gi'
            if (Test-Path $gi) {
                $giFile = Get-Item $gi
                $info['GameFiles'] += [pscustomobject]@{
                    Name = 'gameinfo.gi'; Path = $gi; LastWrite = $giFile.LastWriteTime
                    Hash = (Get-FileHash -LiteralPath $gi -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                }
            }
            # Сторонние dll рядом с бинарниками игры
            $binDirs = @((Join-Path $gameRoot 'game\bin\win64'), (Join-Path $gameRoot 'game\csgo\bin\win64'))
            foreach ($bd in $binDirs) {
                if (-not (Test-Path $bd)) { continue }
                # Дата основной библиотеки игры - ориентир «когда ставилось
                # обновление». Файл заметно новее неё сюда положили отдельно.
                $gameStamp = $null
                $anchor = Join-Path $bd 'client.dll'
                if (Test-Path -LiteralPath $anchor) {
                    $gameStamp = (Get-Item -LiteralPath $anchor).LastWriteTime
                }

                foreach ($dll in (Get-ChildItem $bd -Filter '*.dll' -ErrorAction SilentlyContinue)) {
                    $sig = Get-SigInfo $dll.FullName
                    if (Test-SigOk $sig) { continue }

                    # Valve кладёт в папку игры и неподписанные сторонние
                    # библиотеки, так что сам по себе факт слабый. Настоящий
                    # инжект ловится проверкой модулей внутри cs2.exe.
                    $sev  = 'Low'
                    $note = 'Valve кладёт в папку игры и свои неподписанные библиотеки, так что обычно это не улика. Проверьте целостность файлов игры через Steam.'

                    if ($gameStamp -and $dll.LastWriteTime -gt $gameStamp.AddDays(1)) {
                        $sev  = 'High'
                        $note = 'Файл новее остальных файлов игры - значит, его положили сюда отдельно, а не обновлением.'
                    }

                    Add-Finding $sev 'Игра' ('Неподписанная DLL в папке игры: ' + $dll.Name) `
                        ('Путь: ' + $dll.FullName + ' | Подпись: ' + $sig +
                         ' | Изменён: ' + $dll.LastWriteTime + '. ' + $note)
                }
            }
        }
    } else {
        Add-Finding Low 'Steam' 'Steam не найден в реестре' 'Возможно, пиратская сборка или нестандартная установка.'
    }
    $script:Data['Steam'] = $info
}

# ============================================================================
#  ОТЧЁТ
# ============================================================================

function Get-ReportSummary {
    # Обязательно @(): у пустого результата Where-Object свойство .Count
    # возвращает $null, а не 0, и счётчик в окне рисуется пустым.
    $h = @($script:Findings | Where-Object { $_.Severity -eq 'High'   }).Count
    $m = @($script:Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $l = @($script:Findings | Where-Object { $_.Severity -eq 'Low'    }).Count
    $i = @($script:Findings | Where-Object { $_.Severity -eq 'Info'   }).Count
    [ordered]@{ High = $h; Medium = $m; Low = $l; Info = $i; Total = $script:Findings.Count }
}

function Export-HtmlReport {
    # $Meta - упорядоченный словарь, а не hashtable, поэтому тип не указываем.
    param([string] $Path, $Meta)

    $sum = Get-ReportSummary
    # WebUtility лежит в mscorlib, в отличие от System.Web.HttpUtility,
    # которую пришлось бы доподгружать через Add-Type.
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

    $sev = @{
        High   = @{ Color = '#b3261e'; Label = 'Высокий' }
        Medium = @{ Color = '#b26a00'; Label = 'Средний' }
        Low    = @{ Color = '#6b6b00'; Label = 'Низкий'  }
        Info   = @{ Color = '#2a5d8f'; Label = 'Инфо'    }
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<title>CS2Check - отчёт проверки</title><style>')
    [void]$sb.AppendLine(@'
*{box-sizing:border-box}
body{margin:0;font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;color:#1a1a1a;background:#f5f5f4}
.wrap{max-width:1000px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:19px;margin:40px 0 12px;padding-bottom:8px;border-bottom:1px solid #ddd}
.sub{color:#666;font-size:13px;margin-bottom:24px}
.meta{background:#fff;border:1px solid #e0e0de;border-radius:8px;padding:16px 20px;margin-bottom:24px}
.meta dl{display:grid;grid-template-columns:200px 1fr;gap:6px 16px;margin:0;font-size:13px}
.meta dt{color:#666}
.meta dd{margin:0;font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px}
.tile{flex:1;min-width:120px;background:#fff;border:1px solid #e0e0de;border-radius:8px;padding:14px 16px}
.tile .n{font-size:28px;font-weight:600;line-height:1}
.tile .l{font-size:12px;color:#666;margin-top:4px}
.f{background:#fff;border:1px solid #e0e0de;border-left-width:4px;border-radius:6px;padding:14px 16px;margin-bottom:10px}
.f .top{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.f .badge{font-size:11px;font-weight:600;color:#fff;padding:2px 8px;border-radius:10px;white-space:nowrap}
.f .cat{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.04em}
.f .t{font-weight:600;flex:1 1 100%;margin-top:2px}
.f .d{font-size:13.5px;color:#444;margin-top:6px}
.f details{margin-top:8px}
.f summary{font-size:12px;color:#2a5d8f;cursor:pointer}
.f pre{background:#fafaf9;border:1px solid #eee;border-radius:4px;padding:10px;font-size:11.5px;overflow:auto;max-height:240px;margin:6px 0 0}
table{width:100%;border-collapse:collapse;background:#fff;font-size:12.5px;border:1px solid #e0e0de;border-radius:6px;overflow:hidden}
th{background:#fafaf9;text-align:left;padding:8px 10px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#666;border-bottom:1px solid #e0e0de}
td{padding:7px 10px;border-bottom:1px solid #f0f0ee;vertical-align:top;word-break:break-word}
tr:last-child td{border-bottom:none}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:11.5px}
.ok{background:#fff;border:1px solid #cde5cd;border-left:4px solid #2e7d32;border-radius:6px;padding:16px}
.note{background:#fffbe9;border:1px solid #e8dca0;border-radius:6px;padding:14px 16px;font-size:13px;margin:16px 0}
details.sect>summary{cursor:pointer;font-weight:600;padding:10px 0;font-size:15px}
'@)
    [void]$sb.AppendLine('</style></head><body><div class="wrap">')

    [void]$sb.AppendLine('<h1>CS2Check - отчёт проверки</h1>')
    [void]$sb.AppendLine('<div class="sub">Автоматический сбор следов. Итоговое решение принимает администратор, а не этот отчёт.</div>')

    # --- Метаданные ---
    [void]$sb.AppendLine('<div class="meta"><dl>')
    foreach ($k in $Meta.Keys) {
        [void]$sb.AppendLine('<dt>' + (& $enc $k) + '</dt><dd>' + (& $enc $Meta[$k]) + '</dd>')
    }
    [void]$sb.AppendLine('</dl></div>')

    # --- Плитки ---
    [void]$sb.AppendLine('<div class="tiles">')
    foreach ($s in @('High','Medium','Low','Info')) {
        [void]$sb.AppendLine('<div class="tile"><div class="n" style="color:' + $sev[$s].Color + '">' +
            $sum[$s] + '</div><div class="l">' + $sev[$s].Label + '</div></div>')
    }
    [void]$sb.AppendLine('</div>')

    # --- Находки ---
    [void]$sb.AppendLine('<h2>Находки</h2>')
    if ($script:Findings.Count -eq 0) {
        [void]$sb.AppendLine('<div class="ok"><strong>Автоматические правила ничего не нашли.</strong><br>' +
            'Это не доказательство честной игры: DMA-читы, читы на втором компьютере и аккуратно ' +
            'вычищенные следы такой проверкой не определяются. Смотрите также демки и статистику.</div>')
    } else {
        foreach ($s in @('High','Medium','Low','Info')) {
            $group = $script:Findings | Where-Object { $_.Severity -eq $s }
            foreach ($f in $group) {
                [void]$sb.AppendLine('<div class="f" style="border-left-color:' + $sev[$s].Color + '">')
                [void]$sb.AppendLine('<div class="top"><span class="badge" style="background:' + $sev[$s].Color +
                    '">' + $sev[$s].Label + '</span><span class="cat">' + (& $enc $f.Category) + '</span>')
                [void]$sb.AppendLine('<div class="t">' + (& $enc $f.Title) + '</div></div>')
                if ($f.Detail) { [void]$sb.AppendLine('<div class="d">' + (& $enc $f.Detail) + '</div>') }
                if ($f.Evidence) {
                    $ev = ''
                    try { $ev = ($f.Evidence | ConvertTo-Json -Depth 4 -Compress:$false) } catch { $ev = [string]$f.Evidence }
                    [void]$sb.AppendLine('<details><summary>Технические данные</summary><pre>' + (& $enc $ev) + '</pre></details>')
                }
                [void]$sb.AppendLine('</div>')
            }
        }
    }

    # --- Таблицы сырых данных ---
    function Add-Table {
        param([string] $Title, $Rows, [string[]] $Cols, [int] $Limit = 400)
        if (-not $Rows -or @($Rows).Count -eq 0) { return }
        $rows = @($Rows) | Select-Object -First $Limit
        [void]$sb.AppendLine('<details class="sect"><summary>' + (& $enc $Title) +
            ' (' + @($Rows).Count + ')</summary><table><tr>')
        foreach ($c in $Cols) { [void]$sb.AppendLine('<th>' + (& $enc $c) + '</th>') }
        [void]$sb.AppendLine('</tr>')
        foreach ($r in $rows) {
            [void]$sb.AppendLine('<tr>')
            foreach ($c in $Cols) {
                [void]$sb.AppendLine('<td class="mono">' + (& $enc $r.$c) + '</td>')
            }
            [void]$sb.AppendLine('</tr>')
        }
        [void]$sb.AppendLine('</table></details>')
    }

    [void]$sb.AppendLine('<h2>Собранные данные</h2>')
    [void]$sb.AppendLine('<div class="note">Разделы ниже - сырые данные без оценок. ' +
        'Правила ловят только известные шаблоны, поэтому просматривайте таблицы глазами: ' +
        'незнакомое имя в истории запусков часто важнее любого автоматического флага.</div>')

    Add-Table 'Процессы' $script:Data['Processes'] @('Pid','Name','Path','Signature','StartTime')
    Add-Table 'Модули в cs2.exe' $script:Data['Cs2Modules'] @('Name','Path','Signature','BaseAddress')
    Add-Table 'Prefetch' $script:Data['Prefetch'].Entries @('Name','LastWriteTime','CreationTime')
    Add-Table 'BAM - последние запуски' $script:Data['Bam'] @('Path','LastRun')
    Add-Table 'UserAssist' $script:Data['UserAssist'] @('Name','RunCount','LastRun')
    Add-Table 'Файлы в Загрузках / Temp / Недавних' $script:Data['RecentFiles'] @('Name','FullPath','SizeKB','CreationTime')
    Add-Table 'Работающие драйверы' ($script:Data['Drivers'] | Where-Object { $_.State -eq 'Running' }) @('FileName','DisplayName','Path','Signature')
    if ($script:Data['Usn'] -and $script:Data['Usn'].Hits) {
        Add-Table 'USN-журнал: записи о .exe/.dll/.sys' $script:Data['Usn'].Hits @('FileName','Raw') 1000
    }
    Add-Table 'PCI/USB устройства' $script:Data['PnpDevices'] @('Class','FriendlyName','InstanceId')

    [void]$sb.AppendLine('<h2>Чего эта проверка не определяет</h2>')
    [void]$sb.AppendLine('<div class="note">DMA-читы на отдельной PCIe-плате; чит, запущенный на втором ' +
        'компьютере с картой захвата; аппаратные спуферы мыши; читы в ядре, которые выгрузились до ' +
        'проверки и подчистили артефакты; подсказки с телефона. Чистый отчёт означает «автоматические ' +
        'правила не нашли известных следов», а не «игрок точно играет честно».</div>')

    [void]$sb.AppendLine('</div></body></html>')
    [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
}

# ============================================================================
#  ТОЧКА ВХОДА
# ============================================================================

if (-not $IAgree) {
    if (-not (Show-Consent)) {
        Write-Host ''
        Write-Host '  Согласие не получено. Данные не собирались. Выход.' -ForegroundColor Yellow
        Write-Host ''
        exit 1
    }
}

Write-Host ''
if (-not (Test-IsAdmin)) {
    Write-Host '  [!] Скрипт запущен БЕЗ прав администратора.' -ForegroundColor Yellow
    Write-Host '      Без них недоступны Prefetch, BAM, USN-журнал, список драйверов и' -ForegroundColor Yellow
    Write-Host '      модули cs2.exe - то есть большая часть проверки. Перезапустите' -ForegroundColor Yellow
    Write-Host '      PowerShell от имени администратора.' -ForegroundColor Yellow
    Write-Host ''
    Add-Finding High 'Проверка' 'Скрипт запущен без прав администратора' `
        'Собрана только малая часть данных. Отчёт нельзя считать полноценным - попросите перезапустить от администратора.'
}

$blockPath = Join-Path $PSScriptRoot 'blocklist.txt'
Import-BlockList $blockPath
if ($script:Block.Strict.Count + $script:Block.Loose.Count -gt 0) {
    Write-Host ('  Список: ' + $script:Block.Strict.Count + ' точных, ' +
                $script:Block.Loose.Count + ' спорных, ' +
                $script:Block.Allow.Count + ' в белом списке') -ForegroundColor DarkGray
} else {
    Write-Host '  blocklist.txt не найден - работают только общие шаблоны' -ForegroundColor Yellow
    Add-Finding Info 'Проверка' 'Список запрещённого ПО не загружен' `
        ('Файл blocklist.txt не найден рядом со скриптом, поэтому проверка шла только по ' +
         'общим шаблонам имён. Положите файл рядом и повторите.')
}

Write-Host '  Сбор данных...' -ForegroundColor Cyan
Collect-System
Collect-Processes
Collect-Cs2Modules
Collect-Prefetch
Collect-Bam
Collect-UserAssist
Collect-RecentFiles
Collect-EventLogs
Collect-Drivers
Collect-Steam
Collect-UsnJournal

# Повторы показываем числом в заголовке, а не десятком одинаковых карточек.
foreach ($f in $script:Findings) {
    if ($f.Hits -gt 1) { $f.Title = $f.Title + ' (записей: ' + $f.Hits + ')' }
}

# --- куда писать ---
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path ([Environment]::GetFolderPath('Desktop')) 'CS2Check'
}
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$stamp    = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
$baseName = 'CS2Check_' + $env:COMPUTERNAME + '_' + $stamp
$jsonPath = Join-Path $OutDir ($baseName + '.json')
$htmlPath = Join-Path $OutDir ($baseName + '.html')

$elapsed = [math]::Round(((Get-Date) - $script:StartedAt).TotalSeconds, 1)
$sum     = Get-ReportSummary

$payload = [ordered]@{
    ReportVersion = $script:ScriptVersion
    Token         = $Token
    GeneratedAt   = (Get-Date).ToString('o')
    ElapsedSec    = $elapsed
    RanAsAdmin    = (Test-IsAdmin)
    Summary       = $sum
    Findings      = $script:Findings
    Data          = $script:Data
}
$payload | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8

# Хеш JSON кладём в HTML - так видно, что отчёт не правили руками.
$jsonHash = (Get-FileHash -LiteralPath $jsonPath -Algorithm SHA256).Hash

$tokenText = '(не задан)'
if ($Token) { $tokenText = $Token }
$adminText = 'НЕТ - отчёт неполный'
if (Test-IsAdmin) { $adminText = 'да' }

Export-HtmlReport -Path $htmlPath -Meta ([ordered]@{
    'Компьютер'        = $env:COMPUTERNAME
    'Пользователь'     = $env:USERNAME
    'Токен проверки'   = $tokenText
    'Время сбора'      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    'Длительность'     = ($elapsed.ToString() + ' c')
    'Права админа'     = $adminText
    'Система работает' = ([string]$script:Data['System'].UptimeMinutes + ' мин')
    'Версия скрипта'   = $script:ScriptVersion
    'SHA256 данных'    = $jsonHash
})

# Компактная сводка рядом с полным отчётом: GUI читает её мгновенно,
# тогда как полный JSON с тысячами строк разбирался бы десятки секунд.
$summaryPath = Join-Path $OutDir ($baseName + '.summary.json')
[ordered]@{
    ReportVersion = $script:ScriptVersion
    Token         = $Token
    GeneratedAt   = (Get-Date).ToString('o')
    RanAsAdmin    = (Test-IsAdmin)
    Summary       = $sum
    HtmlPath      = $htmlPath
    JsonPath      = $jsonPath
    JsonSha256    = $jsonHash
    Findings      = @($script:Findings | Select-Object Severity, Category, Title, Detail, Hits)
} | ConvertTo-Json -Depth 4 | Out-File -FilePath $summaryPath -Encoding UTF8

Write-Host ''
Write-Host '  ================================================================' -ForegroundColor Cyan
Write-Host '   Готово.' -ForegroundColor Green
Write-Host ''
Write-Host ('   Высокий риск: ' + $sum.High)   -ForegroundColor $(if ($sum.High   -gt 0) { 'Red' }    else { 'Gray' })
Write-Host ('   Средний:      ' + $sum.Medium) -ForegroundColor $(if ($sum.Medium -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host ('   Низкий:       ' + $sum.Low)    -ForegroundColor Gray
Write-Host ''
Write-Host '   Отчёт для чтения:' -ForegroundColor White
Write-Host ('     ' + $htmlPath)
Write-Host '   Машинные данные:' -ForegroundColor White
Write-Host ('     ' + $jsonPath)
Write-Host ''
Write-Host '   Откройте HTML, прочитайте его - и только потом передавайте админу.' -ForegroundColor Yellow
Write-Host '  ================================================================' -ForegroundColor Cyan
Write-Host ''

if (-not $Quiet) { try { Start-Process $htmlPath } catch {} }

# --- отправка (только с явного согласия в этот момент) ---
if ($ServerUrl -and -not $Quiet) {
    Write-Host '  Отправить отчёт администратору на ' -NoNewline
    Write-Host $ServerUrl -ForegroundColor Cyan
    $ans = Read-Host '  Напишите ОТПРАВИТЬ, чтобы подтвердить'
    if ($ans.Trim().ToUpperInvariant() -in @('ОТПРАВИТЬ','SEND','ДА','YES')) {
        try {
            $body = Get-Content -LiteralPath $jsonPath -Raw -Encoding UTF8
            Invoke-RestMethod -Uri $ServerUrl -Method Post -ContentType 'application/json; charset=utf-8' `
                -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 60 | Out-Null
            Write-Host '  Отчёт отправлен.' -ForegroundColor Green
        } catch {
            Write-Host ('  Не удалось отправить: ' + $_.Exception.Message) -ForegroundColor Red
            Write-Host '  Передайте файл отчёта вручную.' -ForegroundColor Yellow
        }
    } else {
        Write-Host '  Отправка отменена. Файлы остались на вашем компьютере.' -ForegroundColor Yellow
    }
}
