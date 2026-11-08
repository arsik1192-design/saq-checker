# CS2Check - графическая оболочка
# Запускается через «Запустить проверку.bat», который сам просит права администратора.
# Сама проверка живёт в CS2Check.ps1, это окно только управляет ею.

# ============================================================================
#  НАСТРОЙКИ - правьте только этот блок
# ============================================================================

# Куда отправлять отчёт. Пусто = кнопки отправки не будет, игрок шлёт файл руками.
$ServerUrl = ''

# Название вашего проекта в шапке окна.
$ProjectName = 'SAQ.CS.KZ'

# Требовать токен от админа перед запуском. Рекомендуется оставить $true.
$RequireToken = $true

# ============================================================================

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

$script:Root       = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:EnginePath = Join-Path $script:Root 'CS2Check.ps1'
$script:OutDir     = Join-Path ([Environment]::GetFolderPath('Desktop')) 'CS2Check'
$script:Proc       = $null
$script:Started    = $null
$script:Summary    = $null

if (-not (Test-Path $script:EnginePath)) {
    [System.Windows.MessageBox]::Show(
        "Рядом с этим файлом нет CS2Check.ps1.`n`nПоложите оба файла в одну папку и запустите снова.",
        'CS2Check', 'OK', 'Error') | Out-Null
    exit 1
}

# ----------------------------------------------------------------------------
#  Разметка окна
# ----------------------------------------------------------------------------

$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SAQ.CS.KZ" Height="700" Width="620"
        WindowStartupLocation="CenterScreen" ResizeMode="CanMinimize"
        Background="#0B0B0C" FontFamily="Segoe UI">

  <Window.Resources>
    <Style x:Key="Gold" TargetType="Button">
      <Setter Property="Foreground" Value="#14120B"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bg" Background="#C9A227" CornerRadius="4">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bg" Property="Background" Value="#E0BC45"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="bg" Property="Background" Value="#3A3526"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Ghost" TargetType="Button">
      <Setter Property="Foreground" Value="#C9BFA4"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bg" Background="#131314" BorderBrush="#3A3526"
                    BorderThickness="1" CornerRadius="4">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bg" Property="BorderBrush" Value="#C9A227"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Link" TargetType="Button">
      <Setter Property="Foreground" Value="#6F6A5C"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="HorizontalAlignment" Value="Left"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <TextBlock x:Name="t" Text="{TemplateBinding Content}"
                       Foreground="{TemplateBinding Foreground}" FontSize="12"/>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="t" Property="Foreground" Value="#C9A227"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>

    <Border Grid.Row="0" Background="#101011" Padding="24,20"
            BorderBrush="#2E2817" BorderThickness="0,0,0,1">
      <StackPanel>
        <TextBlock x:Name="HeadTitle" Text="SAQ.CS.KZ" Foreground="#D9B85C"
                   FontSize="25" FontWeight="Bold"/>
        <TextBlock x:Name="HeadSub" Text="Проверка компьютера на читы"
                   Foreground="#79725F" FontSize="12.5" Margin="0,4,0,0"/>
      </StackPanel>
    </Border>

    <Grid Grid.Row="1" Margin="24,20,24,22">

      <!-- ЭКРАН 1: согласие -->
      <StackPanel x:Name="ConsentPanel">
        <TextBlock Text="ЧТО ПРОГРАММА СОБИРАЕТ" Foreground="#C9A227"
                   FontSize="11.5" FontWeight="SemiBold"/>
        <Border Background="#111112" BorderBrush="#232017" BorderThickness="1"
                CornerRadius="5" Padding="16,13" Margin="0,9,0,0">
          <TextBlock Foreground="#AEA796" FontSize="12.5" TextWrapping="Wrap" LineHeight="21">
            • список запущенных программ и их цифровые подписи<LineBreak/>
            • библиотеки, загруженные в процесс игры cs2.exe<LineBreak/>
            • историю запуска программ из журналов Windows<LineBreak/>
            • список драйверов и настройки проверки подписи<LineBreak/>
            • записи об удалённых файлах из журнала диска<LineBreak/>
            • имена файлов в папках Загрузки и Temp<LineBreak/>
            • параметры запуска Steam и целостность файлов игры
          </TextBlock>
        </Border>

        <Border Background="#14120B" BorderBrush="#3A3119" BorderThickness="1"
                CornerRadius="5" Padding="16,13" Margin="0,14,0,0">
          <TextBlock Foreground="#B9A878" FontSize="12" TextWrapping="Wrap" LineHeight="19"
                     Text="Отчёт сохранится на ваш Рабочий стол. Вы увидите его раньше администратора и сами решите, отправлять ли. Исходный код открыт - файл CS2Check.ps1 можно открыть Блокнотом и прочитать."/>
        </Border>

        <StackPanel x:Name="TokenRow" Margin="0,20,0,0">
          <TextBlock Text="КОД ПРОВЕРКИ ОТ АДМИНИСТРАТОРА" Foreground="#79725F"
                     FontSize="10.5" FontWeight="SemiBold"/>
          <Border Background="#111112" BorderBrush="#3A3526" BorderThickness="1"
                  CornerRadius="4" Margin="0,7,0,0">
            <TextBox x:Name="TokenBox" Padding="11,9" FontSize="15"
                     Background="Transparent" Foreground="#E9E2D0" BorderThickness="0"
                     CaretBrush="#C9A227" FontFamily="Consolas"/>
          </Border>
        </StackPanel>

        <CheckBox x:Name="AgreeCheck" Margin="0,18,0,0" Foreground="#D6CFBD" FontSize="13"
                  Content="Я согласен на проверку и запускаю её добровольно"/>

        <Button x:Name="StartBtn" Content="НАЧАТЬ ПРОВЕРКУ" Style="{StaticResource Gold}"
                Margin="0,18,0,0" Height="44" FontSize="14"/>

        <TextBlock x:Name="ConsentHint" Foreground="#C4706B" FontSize="12" Margin="0,10,0,0"
                   TextWrapping="Wrap" Text=""/>
      </StackPanel>

      <!-- ЭКРАН 2: процесс -->
      <StackPanel x:Name="ProgressPanel" Visibility="Collapsed" VerticalAlignment="Center">
        <TextBlock Text="ИДЁТ ПРОВЕРКА" Foreground="#C9A227" FontSize="15"
                   FontWeight="SemiBold" HorizontalAlignment="Center"/>
        <TextBlock x:Name="StatusText" Foreground="#8B8472" FontSize="13" Margin="0,10,0,0"
                   HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"
                   Text="Собираем данные..."/>
        <ProgressBar IsIndeterminate="True" Height="4" Margin="0,24,0,0"
                     Background="#1A1A1C" Foreground="#C9A227" BorderThickness="0"/>
        <TextBlock x:Name="ElapsedText" Foreground="#5C5749" FontSize="11.5" Margin="0,14,0,0"
                   HorizontalAlignment="Center" Text=""/>
        <TextBlock Foreground="#5C5749" FontSize="11.5" Margin="0,26,0,0"
                   HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"
                   Text="Обычно занимает от 30 секунд до трёх минут.&#10;Не закрывайте игру и не перезагружайте компьютер."/>
      </StackPanel>

      <!-- ЭКРАН 3: результат -->
      <Grid x:Name="ResultPanel" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock x:Name="ResultTitle" Grid.Row="0" Text="Проверка завершена"
                   Foreground="#EAE3D1" FontSize="17" FontWeight="SemiBold"/>

        <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,15,0,0">
          <Border Background="#111112" BorderBrush="#232017" BorderThickness="1"
                  CornerRadius="5" Padding="16,11" Margin="0,0,10,0" Width="112">
            <StackPanel>
              <TextBlock x:Name="HighCount" Text="0" Foreground="#E05552"
                         FontSize="25" FontWeight="SemiBold"/>
              <TextBlock Text="высокий" Foreground="#79725F" FontSize="11.5"/>
            </StackPanel>
          </Border>
          <Border Background="#111112" BorderBrush="#232017" BorderThickness="1"
                  CornerRadius="5" Padding="16,11" Margin="0,0,10,0" Width="112">
            <StackPanel>
              <TextBlock x:Name="MedCount" Text="0" Foreground="#D9933A"
                         FontSize="25" FontWeight="SemiBold"/>
              <TextBlock Text="средний" Foreground="#79725F" FontSize="11.5"/>
            </StackPanel>
          </Border>
          <Border Background="#111112" BorderBrush="#232017" BorderThickness="1"
                  CornerRadius="5" Padding="16,11" Width="112">
            <StackPanel>
              <TextBlock x:Name="LowCount" Text="0" Foreground="#8C8259"
                         FontSize="25" FontWeight="SemiBold"/>
              <TextBlock Text="низкий" Foreground="#79725F" FontSize="11.5"/>
            </StackPanel>
          </Border>
        </StackPanel>

        <ScrollViewer Grid.Row="2" Margin="0,17,0,0" VerticalScrollBarVisibility="Auto">
          <StackPanel x:Name="FindingsList"/>
        </ScrollViewer>

        <StackPanel Grid.Row="3" Margin="0,15,0,0">
          <TextBlock x:Name="SendStatus" Foreground="#8B8472" FontSize="12"
                     Margin="0,0,0,9" TextWrapping="Wrap" Text=""/>
          <StackPanel Orientation="Horizontal">
            <Button x:Name="OpenBtn" Content="Открыть подробный отчёт"
                    Style="{StaticResource Ghost}" Height="38" Width="220"
                    FontSize="13" Margin="0,0,10,0"/>
            <Button x:Name="SendBtn" Content="Отправить администратору"
                    Style="{StaticResource Gold}" Height="38" Width="220" FontSize="13"/>
          </StackPanel>
          <Button x:Name="FolderBtn" Content="Показать файлы отчёта в папке"
                  Style="{StaticResource Link}" Height="28" Margin="0,11,0,0"/>
        </StackPanel>
      </Grid>

    </Grid>
  </Grid>
</Window>
'@

$ErrorActionPreference = 'Continue'

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$win    = [Windows.Markup.XamlReader]::Load($reader)

$ui = @{}
foreach ($n in @('HeadTitle','HeadSub','ConsentPanel','TokenRow','TokenBox','AgreeCheck',
                 'StartBtn','ConsentHint','ProgressPanel','StatusText','ElapsedText',
                 'ResultPanel','ResultTitle','HighCount','MedCount','LowCount','FindingsList',
                 'OpenBtn','SendBtn','FolderBtn','SendStatus')) {
    $ui[$n] = $win.FindName($n)
}

$ui.HeadTitle.Text = $ProjectName
if (-not $RequireToken) { $ui.TokenRow.Visibility = 'Collapsed' }
if (-not $ServerUrl)    { $ui.SendBtn.Visibility  = 'Collapsed' }

# ----------------------------------------------------------------------------
#  Логика
# ----------------------------------------------------------------------------

function New-Brush {
    # PowerShell не всегда приводит строку "#rrggbb" к Brush при присваивании
    # свойству, поэтому конвертируем явно.
    param([string] $Hex)
    (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Hex)
}

function Show-Panel {
    param([string] $Name)
    $ui.ConsentPanel.Visibility  = 'Collapsed'
    $ui.ProgressPanel.Visibility = 'Collapsed'
    $ui.ResultPanel.Visibility   = 'Collapsed'
    $ui[$Name].Visibility        = 'Visible'
}

function Add-FindingCard {
    param([string] $Severity, [string] $Category, [string] $Title, [string] $Detail)

    $palette = @{
        High   = '#E05552'; Medium = '#D9933A'
        Low    = '#8C8259'; Info   = '#6F8DA8'
    }
    $color = $palette[$Severity]
    if (-not $color) { $color = '#6F8DA8' }

    $bar = New-Object System.Windows.Controls.Border
    $bar.Background      = New-Brush '#111112'
    $bar.CornerRadius    = 4
    $bar.Padding         = '12,10'
    $bar.Margin          = '0,0,0,8'
    $bar.BorderThickness = '3,0,0,0'
    $bar.BorderBrush     = New-Brush $color

    $stack = New-Object System.Windows.Controls.StackPanel

    $cat = New-Object System.Windows.Controls.TextBlock
    $cat.Text       = $Category.ToUpper()
    $cat.Foreground = New-Brush '#6F6A5C'
    $cat.FontSize   = 10
    [void]$stack.Children.Add($cat)

    $ttl = New-Object System.Windows.Controls.TextBlock
    $ttl.Text         = $Title
    $ttl.Foreground   = New-Brush '#EAE3D1'
    $ttl.FontSize     = 13
    $ttl.FontWeight   = 'SemiBold'
    $ttl.TextWrapping = 'Wrap'
    $ttl.Margin       = '0,2,0,0'
    [void]$stack.Children.Add($ttl)

    if ($Detail) {
        $det = New-Object System.Windows.Controls.TextBlock
        $det.Text         = $Detail
        $det.Foreground   = New-Brush '#978F7E'
        $det.FontSize     = 11.5
        $det.TextWrapping = 'Wrap'
        $det.Margin       = '0,4,0,0'
        [void]$stack.Children.Add($det)
    }

    $bar.Child = $stack
    [void]$ui.FindingsList.Children.Add($bar)
}

function Complete-Check {
    # Берём сводку, созданную именно этим запуском. Фильтр по времени нужен,
    # чтобы при неудачной проверке не показать отчёт от прошлого раза.
    $summaryFile = Get-ChildItem -Path $script:OutDir -Filter '*.summary.json' -ErrorAction SilentlyContinue |
                   Where-Object { $_.LastWriteTime -ge $script:Started } |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $summaryFile) {
        Show-Panel 'ResultPanel'
        $ui.ResultTitle.Text = 'Проверка не завершилась'
        Add-FindingCard 'High' 'Ошибка' 'Отчёт не создан' `
            ('Сборщик не оставил файлов в ' + $script:OutDir +
             '. Чаще всего это значит, что программа запущена без прав администратора. ' +
             'Закройте окно и запустите START.bat заново, согласившись на запрос Windows.')
        $ui.SendBtn.Visibility = 'Collapsed'
        $ui.OpenBtn.Visibility = 'Collapsed'
        return
    }

    try {
        $script:Summary = Get-Content -LiteralPath $summaryFile.FullName -Raw -Encoding UTF8 |
                          ConvertFrom-Json
    } catch {
        Show-Panel 'ResultPanel'
        $ui.ResultTitle.Text = 'Не удалось прочитать отчёт'
        Add-FindingCard 'High' 'Ошибка' 'Файл сводки повреждён' $_.Exception.Message
        return
    }

    $s = $script:Summary.Summary
    # Подстраховка: если в сводке пусто, показываем ноль, а не пустую плитку.
    function Fmt { param($v) if ($null -eq $v -or "$v" -eq '') { '0' } else { [string]$v } }
    $ui.HighCount.Text = Fmt $s.High
    $ui.MedCount.Text  = Fmt $s.Medium
    $ui.LowCount.Text  = Fmt $s.Low

    if (-not $script:Summary.RanAsAdmin) {
        $ui.ResultTitle.Text = 'Проверка завершена, но отчёт неполный'
    } elseif ($s.High -gt 0) {
        $ui.ResultTitle.Text = 'Проверка завершена, есть что обсудить'
    } else {
        $ui.ResultTitle.Text = 'Проверка завершена'
    }

    $ui.FindingsList.Children.Clear()
    if (@($script:Summary.Findings).Count -eq 0) {
        Add-FindingCard 'Info' 'Итог' 'Автоматические правила ничего не нашли' `
            ('Это не значит, что проверка что-то гарантирует - она ищет известные следы. ' +
             'Отчёт всё равно разбирает администратор.')
    } else {
        foreach ($sev in @('High','Medium','Low','Info')) {
            foreach ($f in @($script:Summary.Findings | Where-Object { $_.Severity -eq $sev })) {
                Add-FindingCard $f.Severity $f.Category $f.Title $f.Detail
            }
        }
    }

    Show-Panel 'ResultPanel'
}

$script:timer = New-Object System.Windows.Threading.DispatcherTimer
$script:timer.Interval = [TimeSpan]::FromMilliseconds(500)
$script:timer.Add_Tick({
    $sec = [int]((Get-Date) - $script:Started).TotalSeconds
    $ui.ElapsedText.Text = 'прошло ' + $sec + ' с'

    # Длинные шаги подписываем, чтобы окно не выглядело зависшим.
    if     ($sec -lt 10) { $ui.StatusText.Text = 'Смотрим процессы и модули игры...' }
    elseif ($sec -lt 25) { $ui.StatusText.Text = 'Читаем историю запуска программ...' }
    elseif ($sec -lt 45) { $ui.StatusText.Text = 'Проверяем драйверы и настройки системы...' }
    else                 { $ui.StatusText.Text = 'Разбираем журнал файловой системы, это самый долгий шаг...' }

    if ($script:Proc -and $script:Proc.HasExited) {
        $script:timer.Stop()
        Complete-Check
    }
})

$ui.StartBtn.Add_Click({
    if (-not $ui.AgreeCheck.IsChecked) {
        $ui.ConsentHint.Text = 'Отметьте согласие - без него проверка не запускается.'
        return
    }
    $token = $ui.TokenBox.Text.Trim()
    if ($RequireToken -and -not $token) {
        $ui.ConsentHint.Text = 'Введите код проверки, который дал администратор.'
        return
    }

    # Код сверяем с панелью ДО сканирования: иначе игрок ждёт три минуты
    # и только в конце узнаёт, что код не тот.
    if ($ServerUrl -and $token) {
        $ui.ConsentHint.Text = 'Проверяем код...'
        $win.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background,
                               [System.Action]{})
        $verifyUrl = $ServerUrl -replace 'receive\.php$', 'verify.php'
        try {
            $vr = Invoke-RestMethod -TimeoutSec 15 -Uri (
                $verifyUrl + '?token=' + [uri]::EscapeDataString($token))
            if (-not $vr.ok) {
                $ui.ConsentHint.Text = $vr.error
                return
            }
        } catch {
            # Панель недоступна - не блокируем проверку из-за сети.
            # Код всё равно будет проверен при отправке отчёта.
        }
        $ui.ConsentHint.Text = ''
    }

    Show-Panel 'ProgressPanel'
    $script:Started = Get-Date

    $psArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $script:EnginePath + '"'),
        '-IAgree', '-Quiet', '-OutDir', ('"' + $script:OutDir + '"')
    )
    if ($token) { $psArgs += @('-Token', ('"' + $token + '"')) }

    try {
        $script:Proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $psArgs `
                       -WindowStyle Hidden -PassThru
        $script:timer.Start()
    } catch {
        Show-Panel 'ResultPanel'
        $ui.ResultTitle.Text = 'Не удалось запустить проверку'
        Add-FindingCard 'High' 'Ошибка' 'PowerShell не стартовал' $_.Exception.Message
    }
})

$ui.OpenBtn.Add_Click({
    if ($script:Summary -and $script:Summary.HtmlPath) {
        try { Start-Process $script:Summary.HtmlPath } catch {}
    }
})

$ui.FolderBtn.Add_Click({
    try { Start-Process 'explorer.exe' -ArgumentList $script:OutDir } catch {}
})

$ui.SendBtn.Add_Click({
    if (-not $script:Summary) { return }
    $ui.SendBtn.IsEnabled = $false
    $ui.SendStatus.Foreground = New-Brush '#8B8472'
    $ui.SendStatus.Text = 'Отправляем...'
    $win.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [System.Action]{})

    try {
        $body = Get-Content -LiteralPath $script:Summary.JsonPath -Raw -Encoding UTF8
        $resp = Invoke-RestMethod -Uri $ServerUrl -Method Post -TimeoutSec 90 `
                -ContentType 'application/json; charset=utf-8' `
                -Body ([Text.Encoding]::UTF8.GetBytes($body))
        $ui.SendStatus.Foreground = New-Brush '#7FAE6F'
        $ui.SendStatus.Text = 'Отчёт отправлен администратору. Можно закрывать окно.'
        $ui.SendBtn.Content = 'Отправлено'
    } catch {
        $ui.SendBtn.IsEnabled = $true
        $ui.SendStatus.Foreground = New-Brush '#c47b7b'
        $ui.SendStatus.Text = 'Не удалось отправить: ' + $_.Exception.Message +
                              '. Нажмите «Показать файлы отчёта в папке» и передайте файл вручную.'
    }
})

$win.Add_Closing({
    if ($script:Proc -and -not $script:Proc.HasExited) {
        # Проверка идёт в отдельном процессе - закрытие окна не должно
        # оставлять его висеть в фоне.
        try { $script:Proc.Kill() } catch {}
    }
    $script:timer.Stop()
})

# Прав администратора нет - показываем понятный экран вместо формы согласия.
# Раньше START.bat повышал права сам, но приём "Start-Process -Verb RunAs"
# сильно нервирует антивирусы, поэтому теперь просим об этом игрока явно.
$amAdmin = $false
try {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $amAdmin = (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

if (-not $amAdmin) {
    Show-Panel 'ResultPanel'
    $ui.ResultTitle.Text     = 'Нужны права администратора'
    $ui.SendBtn.Visibility   = 'Collapsed'
    $ui.OpenBtn.Visibility   = 'Collapsed'
    $ui.FolderBtn.Visibility = 'Collapsed'
    Add-FindingCard 'High' 'Запуск' 'Закройте окно и запустите заново' `
        ('Нажмите на файл START.bat правой кнопкой мыши и выберите ' +
         '"Запуск от имени администратора". Без этих прав недоступны журналы ' +
         'запуска программ, список драйверов, журнал диска и библиотеки внутри ' +
         'игры - то есть почти всё, что проверяется.')
}

[void]$win.ShowDialog()
