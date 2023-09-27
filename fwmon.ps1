### fwmon
$applicationName = "Firewall Monitor"
$applicationVersion = "1.0.0.1"

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

# Check Security Log Read permission
Try {Get-WinEvent -LogName security -MaxEvents 1 -ErrorAction Stop | Out-Null} catch {  
    [System.Windows.MessageBox]::Show(($PSCommandPath.Substring(($PSCommandPath.LastIndexOf("\") + 1),($PSCommandPath.Length - $PSCommandPath.LastIndexOf("\") - 1)) , "requires Windows Security Event Log Read Access"), "Execution aborted" , 0, 16)
    Exit
}

$initial_console_title = (get-host).UI.RawUI.WindowTitle
$ConsoleTitle = $applicationName + " Console"
$Host.UI.RawUI.WindowTitle = $ConsoleTitle

Do {Start-Sleep -Milliseconds 50} Until (Get-Process | ? {$_.MainWindowTitle -eq $ConsoleTitle})
$ConsoleHandle = (Get-Process | ? {$_.MainWindowTitle -eq $ConsoleTitle}).MainWindowHandle

[System.Collections.ArrayList]$Global:EventsArr = [System.Collections.ArrayList]::new()
# Initial Value of Event Buffer Max Length
[int32]$Global:EventsArrMaxLength = 1000

$MessagesColor = "Yellow"

Write-Host "Welcome!" -ForegroundColor $MessagesColor -NoNewline
Write-Host "`n`nStarting GUI..." -ForegroundColor $MessagesColor

[xml]$XAMLMainWindow = @"
<Window x:Name="Window_Main"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        Height="81" Width="500" ResizeMode="NoResize" WindowStyle="None" SnapsToDevicePixels="True"  IsTabStop="False" BorderThickness="1" BorderBrush="{DynamicResource {x:Static SystemColors.ControlDarkBrushKey}}">
    <Grid Background="#FFE6E6E6">
        <Button x:Name="Button_Go" Content="Go" HorizontalAlignment="Left" VerticalAlignment="Top" Width="55" Margin="7,4,0,0"/>
        <Button x:Name="Button_Stop" Content="Stop" HorizontalAlignment="Left" Margin="67,4,0,0" VerticalAlignment="Top" Width="55" Height="20" IsEnabled="False"/>
        <Button x:Name="Button_outTXT" Content=">Txt" HorizontalAlignment="Left" Margin="311,4,0,0" VerticalAlignment="Top" Width="44" IsEnabled="False"/>
        <Button x:Name="Button_outExcel" Content=">Excel" HorizontalAlignment="Left" Margin="362,4,0,0" VerticalAlignment="Top" Width="51" IsEnabled="{Binding ElementName=Button_outTXT, Path=IsEnabled, Mode=OneWay}"/>
        <Button x:Name="Button_Exit" HorizontalAlignment="Left" Margin="475,6,0,0" VerticalAlignment="Top" Width="19" Height="19" Padding="0,0,0,0" BorderThickness="0" Background="#FFE6E6E6">
            <Grid Height="19" Width="19" RenderTransformOrigin="0.5,0.5">
                <Rectangle Height="2" Stroke="#FF333333" Margin="-2,0,0,0" RenderTransformOrigin="0.5,0.5" Width="23">
                    <Rectangle.RenderTransform>
                        <TransformGroup>
                            <ScaleTransform/>
                            <SkewTransform/>
                            <RotateTransform Angle="45"/>
                            <TranslateTransform/>
                        </TransformGroup>
                    </Rectangle.RenderTransform>
                </Rectangle>
                <Rectangle Height="2" Stroke="#FF333333" RenderTransformOrigin="0.5,0.5" Margin="-2,-1,0,0">
                    <Rectangle.RenderTransform>
                        <TransformGroup>
                            <ScaleTransform/>
                            <SkewTransform/>
                            <RotateTransform Angle="-45"/>
                            <TranslateTransform/>
                        </TransformGroup>
                    </Rectangle.RenderTransform>
                </Rectangle>
            </Grid>
        </Button>
        <Button x:Name="Button_Hide" HorizontalAlignment="Left" Margin="445,6,0,0" VerticalAlignment="Top" Width="19" Height="19" BorderThickness="0" Background="#FFE6E6E6">
            <Rectangle Height="2" Stroke="#FF333333" Width="16" StrokeThickness="2" Margin="-1,0,0,-12" HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Button>

        <Button x:Name = "ButtonSecPol" Content="SecPol" HorizontalAlignment="Left" Margin="192,4,0,0" VerticalAlignment="Top" Width="49"/>
        <Button x:Name = "ButtonWF" Content="WF" HorizontalAlignment="Left" Margin="247,4,0,0" VerticalAlignment="Top" Width="47" RenderTransformOrigin="0.176,0.217"/>

        <Rectangle HorizontalAlignment="Left" Height="1" Margin="1,28,0,0" Stroke="#FF858585" VerticalAlignment="Top" Width="496"/>
        <Rectangle Fill="#FFF4F4F5" HorizontalAlignment="Left" Height="28" Margin="129,0,0,0" Stroke="#FF858585" VerticalAlignment="Top" Width="1"/>
        <Rectangle Fill="#FFF4F4F5" HorizontalAlignment="Left" Height="28" Margin="301,0,0,0" Stroke="#FF858585" VerticalAlignment="Top" Width="1"/>
        <Rectangle Fill="#FFF4F4F5" HorizontalAlignment="Left" Height="28" Margin="421,0,0,0" Stroke="#FF858585" VerticalAlignment="Top" Width="1"/>
        <Rectangle Fill="#FFF4F4F5" HorizontalAlignment="Left" Height="79" Margin="499,0,0,0" Stroke="#FF858585" VerticalAlignment="Top" Width="1"/>

        <CheckBox x:Name="CheckBox_IPv4" Content="IPv4" HorizontalAlignment="Left" Margin="9,35,0,0" VerticalAlignment="Top" IsChecked="True" IsEnabled="False"/>
        <CheckBox x:Name="CheckBox_IPv6" Content="IPv6" HorizontalAlignment="Left" Margin="60,35,0,0" VerticalAlignment="Top" IsChecked="False"/>
        <CheckBox x:Name="CheckBox_DNS" Content="DNS" HorizontalAlignment="Left" Margin="172,35,0,0" VerticalAlignment="Top" IsChecked="False"/>
        <CheckBox x:Name="CheckBox_DHCP" Content="DHCP" HorizontalAlignment="Left" Margin="225,35,0,0" VerticalAlignment="Top" IsChecked="False"/>
        <CheckBox x:Name="CheckBox_Other" Content="Other" HorizontalAlignment="Left" Margin="284,35,0,0" VerticalAlignment="Top" IsChecked="False"/>
        <CheckBox x:Name="CheckBox_Global" Content="Global" HorizontalAlignment="Left" Margin="111,35,0,0" VerticalAlignment="Top" IsChecked="True"/>
        <CheckBox x:Name="CheckBox_Past" Content="Past" HorizontalAlignment="Left" Margin="449,35,0,0" VerticalAlignment="Top" IsEnabled="{Binding ElementName=Button_Go, Path=IsEnabled}">
            <CheckBox.ToolTip>
                <ToolTip Background="{DynamicResource {x:Static SystemColors.InfoBrushKey}}">Show past firewall events</ToolTip>
            </CheckBox.ToolTip>
        </CheckBox>

        <TextBox x:Name="TextBox_MarkText" HorizontalAlignment="Left" Height="17" Margin="263,57,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="122">
            <TextBox.ToolTip>
                <ToolTip Background="{DynamicResource {x:Static SystemColors.InfoBrushKey}}">Mark lines including text</ToolTip>
            </TextBox.ToolTip>
        </TextBox>

        <TextBox x:Name="TextBox_MatchText" HorizontalAlignment="Left" Height="17" Margin="55,57,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="161">
            <TextBox.ToolTip>
                <ToolTip Background="{DynamicResource {x:Static SystemColors.InfoBrushKey}}">Text filters comma separated, NOT filter with prefix "!"</ToolTip>
            </TextBox.ToolTip>
        </TextBox>

        <Label Content="Mark:" HorizontalAlignment="Left" Margin="221,52,0,0" VerticalAlignment="Top" Height="27"/>
        <Label Content="Match:" HorizontalAlignment="Left" Height="24" Margin="9,52,0,0" VerticalAlignment="Top" Width="86"/>

        <Button x:Name ="ButtonWholeWindow" Content="" HorizontalAlignment="Left" Margin="0,0,0,-1" VerticalAlignment="Top" Width="{Binding ElementName=Window_Main ,Path=ActualWidth, Mode=OneWay}" Height="{Binding ElementName=Window_Main ,Path=ActualHeight, Mode=OneWay}" BorderThickness="0,0,0,0.1" BorderBrush="{x:Null}" Opacity="0" Visibility="Hidden"/>
        <Button x:Name="Button_FilterId" Content="FilterId" HorizontalAlignment="Left" Margin="137,4,0,0" VerticalAlignment="Top" Width="49"/>
        <TextBox x:Name="Window_Main_TextBox_Buffer" HorizontalAlignment="Left" Margin="420,55,0,0" Text="10000" VerticalAlignment="Top" Width="71" InputScope="Digits" Height="20" TextWrapping="NoWrap">
            <TextBox.ContextMenu>
                <ContextMenu Visibility ="Collapsed"/>
            </TextBox.ContextMenu>
            <TextBox.ToolTip>
                <TextBlock>  
                        While realtime monitoring it is Max number of events in memory buffer, same as outFile max capacity.
                        <LineBreak/>
                        Max value 2 147 483 647 events. 0 means never stop writing to RAM (seems to be bad idea).
                </TextBlock>
            </TextBox.ToolTip>
        </TextBox>
        <Label Content="Buf:" HorizontalAlignment="Left" Margin="390,52,0,0" VerticalAlignment="Top"/>

    </Grid>
</Window>
"@

[xml]$XAMLPastEventsWindow = @"
<Window x:Name="Window_PastEvents"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        Title="PastEvents" Height="116" Width="187" ResizeMode="NoResize" WindowStyle="None" SnapsToDevicePixels="True"  IsTabStop="False" BorderThickness="1" BorderBrush="{DynamicResource {x:Static SystemColors.ControlDarkBrushKey}}">
    <Grid Background="#FFF4F4F4">

        <StackPanel x:Name="PastEventsWindow_StackPanel_Upper" HorizontalAlignment="Left" Height="63" VerticalAlignment="Top" Width="185" IsEnabled="False">
            <Grid>
                <TextBox x:Name="PastEventsWindow_TextBox_SY" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="36" HorizontalContentAlignment="Center" Margin="36,5,0,0" />
                <TextBox x:Name="PastEventsWindow_TextBox_SM" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="20" HorizontalContentAlignment="Center" Margin="72,5,0,0"/>
                <TextBox x:Name="PastEventsWindow_TextBox_SD" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="20" HorizontalContentAlignment="Center" Margin="92,5,0,0"/>
                <TextBox x:Name="PastEventsWindow_TextBox_SH" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="20" HorizontalContentAlignment="Center" Margin="117,5,0,0"/>
                <TextBox x:Name="PastEventsWindow_TextBox_SMt" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="20" HorizontalContentAlignment="Center" Margin="137,5,0,0"/>
                <TextBox x:Name="PastEventsWindow_TextBox_SS" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="20" HorizontalContentAlignment="Center" Margin="155,5,0,0"/>
                <TextBox x:Name="PastEventsWindow_TextBox_TY" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="36" HorizontalContentAlignment="Center" Margin="36,38,0,0"/>
                <TextBox x:Name="PastEventsWindow_TextBox_TM" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="20" HorizontalContentAlignment="Center" Margin="72,38,0,0"/>
                <TextBox x:Name="PastEventsWindow_TextBox_TD" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="20" HorizontalContentAlignment="Center" Margin="92,38,0,0"/>
                <TextBox x:Name="PastEventsWindow_TextBox_TH" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="20" HorizontalContentAlignment="Center" Margin="117,38,0,0"/>
                <TextBox x:Name="PastEventsWindow_TextBox_TMt" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="20" HorizontalContentAlignment="Center" Margin="137,38,0,0"/>
                <TextBox x:Name="PastEventsWindow_TextBox_TS" HorizontalAlignment="Left" Height="18" TextWrapping="NoWrap" Text="" VerticalAlignment="Top" Width="20" HorizontalContentAlignment="Center" Margin="155,38,0,0"/>
                <Label Content="Y      &#x2009;M   &#x2009;D     &#x2009;H  &#x2009;&#x2009;M   &#x2009;S" HorizontalAlignment="Left" VerticalAlignment="Top" Width="129" HorizontalContentAlignment="Left" Foreground="#FF8F0909" FontSize="11" Height="24" Margin="46,18,0,0" />
                <Button x:Name="PastEventsWindow_Button_since" Content="since::" HorizontalAlignment="Left" Margin="4,5,0,0" Width="32" Height="18" VerticalAlignment="Top" HorizontalContentAlignment="Right" BorderThickness="0"/>
                <Button x:Name="PastEventsWindow_Button_till" Content="till:" HorizontalAlignment="Left" Margin="3,38,0,0" Width="32" Height="18" VerticalAlignment="Top" HorizontalContentAlignment="Right" BorderThickness="0"/>
            </Grid>
        </StackPanel>

        <CheckBox x:Name="PastEventsWindow_CheckBox_last" Content="" HorizontalAlignment="Left" Margin="32,81,0,0" VerticalAlignment="Top" IsChecked="True"/>
        <Label Content="last" HorizontalAlignment="Left" Height="23" Margin="6,74,0,0" VerticalAlignment="Top" Width="29"/>
        <TextBox x:Name="PastEventsWindow_TextBox_last" HorizontalAlignment="Left" Height="18" Margin="54,79,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="45" HorizontalContentAlignment="Center" Text="1" IsEnabled="{Binding ElementName=PastEventsWindow_CheckBox_last ,Path=IsChecked, Mode=OneWay}"/>
        <StackPanel x:Name="PastEventsWindow_StackPanel_Lower" HorizontalAlignment="Left" Height="46" Margin="104,66,0,0" VerticalAlignment="Top" Width="69" IsEnabled="{Binding ElementName=PastEventsWindow_CheckBox_last ,Path=IsChecked, Mode=OneWay}">
            <RadioButton x:Name="RadioButton_minutes" Content="minutes" IsChecked="True"/>
            <RadioButton x:Name="RadioButton_hours" Content="hours"/>
            <RadioButton x:Name="RadioButton_days" Content="days" Height="17"/>
        </StackPanel>
        <Rectangle HorizontalAlignment="Left" Height="1" Margin="0,63,0,0" Stroke="#FF858585" VerticalAlignment="Top" Width="185"/>

    </Grid>
</Window>
"@

try { $Window_main = [Windows.Markup.XamlReader]::Load($(New-Object System.Xml.XmlNodeReader $XAMLMainWindow)) } catch { Write-Warning $_.Exception ; throw }
try { $Window_PastEvents = [Windows.Markup.XamlReader]::Load($(New-Object System.Xml.XmlNodeReader $XAMLPastEventsWindow)) } catch { Write-Warning $_.Exception ; throw }

$XAMLMainWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | % { New-Variable  -Name $_.Name -Value $Window_main.FindName($_.Name) -Force -ErrorAction SilentlyContinue}
$XAMLPastEventsWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | % { New-Variable  -Name $_.Name -Value $Window_PastEvents.FindName($_.Name) -Force -ErrorAction SilentlyContinue}

Function Get-Window {
    [OutputType('System.Automation.WindowInfo')]
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipelineByPropertyName=$True)]
        $Handle
    )
    Begin {
        Try{
            [void][Window]
        } Catch {
        Add-Type @"
              using System;
              using System.Runtime.InteropServices;
              public class Window {
                [DllImport("user32.dll")]
                [return: MarshalAs(UnmanagedType.Bool)]
                public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

                [DllImport("User32.dll")]
                public extern static bool MoveWindow(IntPtr handle, int x, int y, int width, int height, bool redraw);
              }
              public struct RECT
              {
                public int Left;        // x position of upper-left corner
                public int Top;         // y position of upper-left corner
                public int Right;       // x position of lower-right corner
                public int Bottom;      // y position of lower-right corner
              }
"@
        }
    }
    Process {
        $Rectangle = New-Object RECT
        $Window = [Window]::GetWindowRect($Handle,[ref]$Rectangle)
        Return $Rectangle
    }
}


$Window_main.add_MouseLeftButtonDown({$Window_main.DragMove()})

$ButtonWholeWindow.Add_Click.Invoke({
   $Window_main.OwnedWindows | % {$_.Hide()}
   $ButtonWholeWindow.Visibility = "Hidden"
})    

$CheckBox_Past.Add_Checked({
    if (-Not ($Global:DateTimeAlreadySetted)) { # Установка начальных дат Since и Till в $Windows_PastEvents
        $Global:DateTimeAlreadySetted = $true
        $Now = Get-Date
        $PastEventsWindow_TextBox_SY.Text = ($now.Year).tostring("0000")
        $PastEventsWindow_TextBox_SM.Text = ($now.Month).tostring("00")
        $PastEventsWindow_TextBox_SD.Text = ($now.Day).tostring("00")
        $PastEventsWindow_TextBox_SH.Text = (0).tostring("00")
        $PastEventsWindow_TextBox_SMt.Text = (0).tostring("00")
        $PastEventsWindow_TextBox_SS.Text = (0).tostring("00")
        $PastEventsWindow_TextBox_TY.Text = ($now.Year).tostring("00")
        $PastEventsWindow_TextBox_TM.Text = ($now.Month).tostring("00")
        $PastEventsWindow_TextBox_TD.Text = ($now.Day).tostring("00")
        $PastEventsWindow_TextBox_TH.Text = ($now.Hour).tostring("00")
        $PastEventsWindow_TextBox_TMt.Text = ($now.Minute).tostring("00")
        $PastEventsWindow_TextBox_TS.Text = ($now.Second).tostring("00")
        Remove-Variable Now
    }
    $Window_PastEvents.Owner = $Window_main
    $Window_PastEvents.Left = $Window_main.Left + $CheckBox_Past.Margin.Left - $Window_PastEvents.Width/2
    $Window_PastEvents.Top = $Window_main.Top + $CheckBox_Past.Margin.Top
    $ButtonWholeWindow.Visibility = "Visible"
    $Window_PastEvents.Focus()
    $Window_PastEvents.Show()
})

$PastEventsWindow_CheckBox_last.Add_Checked({ $PastEventsWindow_StackPanel_Upper.IsEnabled = $False })

$PastEventsWindow_CheckBox_last.Add_UnChecked({
    $PastEventsWindow_StackPanel_Upper.IsEnabled = $True
    $PastEventsWindow_TextBox_SY.Focus()
})

$OnPaste = {
    Param (
        [object]$sender,
        [System.Windows.DataObjectPastingEventArgs]$e
    )
    $e.CancelCommand()
}
[System.Windows.DataObject]::AddPastingHandler($Window_Main_TextBox_Buffer,$OnPaste)

$Window_Main_TextBox_Buffer.Add_PreviewTextInput({
    Param(
        [Parameter(Mandatory)][Object]$sender,
        [Parameter(Mandatory)][System.Windows.Input.TextCompositionEventArgs]$e
    )
    if ($e.Text -notmatch '^\d$') {$e.Handled = $true} else {
        if ([double]($Window_Main_TextBox_Buffer.Text.Insert($this.SelectionStart,$e.Text)) -gt 2147483647) {$e.Handled = $true} else {
            #$Window_Main_TextBox_Buffer.Text + $e.Text | out-host
        }
    }
})

$Window_Main_TextBox_Buffer.Add_TextChanged({
    if ($Window_Main_TextBox_Buffer.Text -eq "") {$Window_Main_TextBox_Buffer.Text = "0"}
    $Global:EventsArrMaxLength = [int32]$Window_Main_TextBox_Buffer.Text
    $SyncHash.Parent_EventsArrMaxLength = $Global:EventsArrMaxLength
})

$PastEventsWindow_TextBox_SY.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_SM.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_SD.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_SH.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_SMt.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_SS.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_TY.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_TM.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_TD.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_TH.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_TMt.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })
$PastEventsWindow_TextBox_TS.Add_GotFocus({ $this.SelectionStart = 0 ; $this.SelectionLength =  $this.Text.Length })

$PastEventsWindow_TextBox_SY.Add_LostFocus({$this.Text = '{0:d4}' -f [int]$this.Text})
$PastEventsWindow_TextBox_TY.Add_LostFocus({$this.Text = '{0:d4}' -f [int]$this.Text})

$PastEventsWindow_TextBox_SM.Add_LostFocus({$this.Text = '{0:d2}' -f [int]$this.Text})
$PastEventsWindow_TextBox_SD.Add_LostFocus({$this.Text = '{0:d2}' -f [int]$this.Text})
$PastEventsWindow_TextBox_SH.Add_LostFocus({$this.Text = '{0:d2}' -f [int]$this.Text})
$PastEventsWindow_TextBox_SMt.Add_LostFocus({$this.Text = '{0:d2}' -f [int]$this.Text})
$PastEventsWindow_TextBox_SS.Add_LostFocus({$this.Text = '{0:d2}' -f [int]$this.Text})
$PastEventsWindow_TextBox_TM.Add_LostFocus({$this.Text = '{0:d2}' -f [int]$this.Text})
$PastEventsWindow_TextBox_TD.Add_LostFocus({$this.Text = '{0:d2}' -f [int]$this.Text})
$PastEventsWindow_TextBox_TH.Add_LostFocus({$this.Text = '{0:d2}' -f [int]$this.Text})
$PastEventsWindow_TextBox_TMt.Add_LostFocus({$this.Text = '{0:d2}' -f [int]$this.Text})
$PastEventsWindow_TextBox_TS.Add_LostFocus({$this.Text = '{0:d2}' -f [int]$this.Text})

Function NDigitsTextBox {`
    param($Input_TextBox,$Next_TextBox,$MaxLength)

    if ($Input_TextBox.Text -match '[^0-9]') {
        $cursorPos = $Input_TextBox.SelectionStart
        $Input_TextBox.Text = $Input_TextBox.Text -replace '[^0-9]',''
        $Input_TextBox.SelectionStart = $cursorPos - 1
        $Input_TextBox.SelectionLength = 0
    }
    if ($Input_TextBox.Text.Length -eq $MaxLength) {
        $Next_TextBox.Focus()
    }
    if ($Input_TextBox.Text.Length -gt $MaxLength) {
        $cursorPos = $Input_TextBox.SelectionStart
        $Input_TextBox.Text = $Input_TextBox.Text.Substring(0,$MaxLength)
        $Input_TextBox.SelectionStart = $cursorPos - 1
        $Input_TextBox.SelectionLength = 0
        $Next_TextBox.Focus()
    }
}

$PastEventsWindow_TextBox_SY.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_SM 4})
$PastEventsWindow_TextBox_SM.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_SD 2})
$PastEventsWindow_TextBox_SD.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_SH 2})
$PastEventsWindow_TextBox_SH.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_SMt 2})
$PastEventsWindow_TextBox_SMt.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_SS 2})
$PastEventsWindow_TextBox_SS.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_TY 2})
$PastEventsWindow_TextBox_TY.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_TM 4})
$PastEventsWindow_TextBox_TM.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_TD 2})
$PastEventsWindow_TextBox_TD.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_TH 2})
$PastEventsWindow_TextBox_TH.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_TMt 2})
$PastEventsWindow_TextBox_TMt.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_TS 2})
#$PastEventsWindow_TextBox_TS.Add_TextChanged({ NDigitsTextBox $this $PastEventsWindow_TextBox_SY 2})
$PastEventsWindow_TextBox_last.Add_TextChanged({NDigitsTextBox $this $this 6})

# CheckBox_IPv4
$CheckBox_IPv4.Add_Checked({
    Try {$SyncHash.Parent_CheckBox_IPv4_IsChecked = $CheckBox_IPv4.IsChecked} catch {}
    $CheckBox_IPv6.IsEnabled = $true
})
$CheckBox_IPv4.Add_UnChecked({
    Try {$SyncHash.Parent_CheckBox_IPv4_IsChecked = $CheckBox_IPv4.IsChecked} catch {}
    $CheckBox_IPv6.IsEnabled = $false
})

# CheckBox_IPv6
$CheckBox_IPv6.Add_Checked({
    Try {$SyncHash.Parent_CheckBox_IPv6_IsChecked = $CheckBox_IPv6.IsChecked} catch {}
    $CheckBox_IPv4.IsEnabled = $true
})
$CheckBox_IPv6.Add_UnChecked({
    Try {$SyncHash.Parent_CheckBox_IPv6_IsChecked = $CheckBox_IPv6.IsChecked} catch {}
    $CheckBox_IPv4.IsEnabled = $false
})

# CheckBox_DNS
$CheckBox_DNS.Add_Checked({
    Try {$SyncHash.Parent_CheckBox_DNS_IsChecked = $CheckBox_DNS.IsChecked} catch {}
})
$CheckBox_DNS.Add_UnChecked({
    Try {$SyncHash.Parent_CheckBox_DNS_IsChecked = $CheckBox_DNS.IsChecked} catch {}
})

# CheckBox_DHCP
$CheckBox_DHCP.Add_Checked({
    Try {$SyncHash.Parent_CheckBox_DHCP_IsChecked = $CheckBox_DHCP.IsChecked} catch {}
})
$CheckBox_DHCP.Add_UnChecked({
    Try {$SyncHash.Parent_CheckBox_DHCP_IsChecked = $CheckBox_DHCP.IsChecked} catch {}
})

# CheckBox_Other
$CheckBox_Other.Add_Checked({
    Try {$SyncHash.Parent_CheckBox_Other_IsChecked = $CheckBox_Other.IsChecked} catch {}
})
$CheckBox_Other.Add_UnChecked({
    Try {$SyncHash.Parent_CheckBox_Other_IsChecked = $CheckBox_Other.IsChecked} catch {}
})

# CheckBox_Global
$CheckBox_Global.Add_Checked({
    Try {$SyncHash.Parent_CheckBox_Global_IsChecked = $CheckBox_Global.IsChecked} catch {}
})
$CheckBox_Global.Add_UnChecked({
    Try {$SyncHash.Parent_CheckBox_Global_IsChecked = $CheckBox_Global.IsChecked} catch {}
})

# TextBox_MarkText
$TextBox_MarkText.AddHandler([System.Windows.Controls.Primitives.TextBoxBase]::TextChangedEvent,[System.Windows.RoutedEventHandler]`
{
    Try {$SyncHash.Parent_TextBox_MarkText_Text = $TextBox_MarkText.Text} catch {}
})

# TextBox_MatchText
$TextBox_MatchText.AddHandler([System.Windows.Controls.Primitives.TextBoxBase]::TextChangedEvent,[System.Windows.RoutedEventHandler]`
{
    Try {$SyncHash.Parent_TextBox_MatchText_Text = $TextBox_MatchText.Text} catch {}
})

# Button_Stop
$Button_Stop.add_Click.Invoke({
    $Button_Go.IsEnabled = $True
    $Button_Stop.IsEnabled = $False
    $Global:Watcher.Enabled = $False
    #$Global:psCmd.EndStop($Global:psCmd.BeginStop($null,$Global:RunspaceHandle))
    Write-Host $((Get-Date).ToString("yyyy/MM/dd HH:mm:ss")) -no ; Write-Host " Stop Events subscriber" -ForegroundColor $MessagesColor
    Write-Host "Waiting for commands" -ForegroundColor $MessagesColor

})

# Buttins since и till
$PastEventsWindow_Button_since.add_Click({
    $Now = Get-Date
    $PastEventsWindow_TextBox_SY.Text = ($now.Year).tostring("0000")
    $PastEventsWindow_TextBox_SM.Text = ($now.Month).tostring("00")
    $PastEventsWindow_TextBox_SD.Text = ($now.Day).tostring("00")
    $PastEventsWindow_TextBox_SH.Text = (0).tostring("00")
    $PastEventsWindow_TextBox_SMt.Text = (0).tostring("00")
    $PastEventsWindow_TextBox_SS.Text = (0).tostring("00")
    Remove-Variable Now
})
$PastEventsWindow_Button_till.add_Click({
    $Now = Get-Date
    $PastEventsWindow_TextBox_TY.Text = ($now.Year).tostring("00")
    $PastEventsWindow_TextBox_TM.Text = ($now.Month).tostring("00")
    $PastEventsWindow_TextBox_TD.Text = ($now.Day).tostring("00")
    $PastEventsWindow_TextBox_TH.Text = ($now.Hour).tostring("00")
    $PastEventsWindow_TextBox_TMt.Text = ($now.Minute).tostring("00")
    $PastEventsWindow_TextBox_TS.Text = ($now.Second).tostring("00")
    Remove-Variable Now
})

# toTXT
$Button_outTXT.add_Click.Invoke({
    Get-ChildItem -Path "$env:TEMP\fwmon*.t*" | ForEach-Object {Remove-Item $_ -Force -ErrorAction SilentlyContinue}
    $FileName = "$env:TEMP\fwmon_" + (Get-Date).ToString("yyyyMMdd-HHmmss") + ".txt"
    "RecordID;Date;Time;ProcessID;ApplicationFullPath;FirewallRule#;Action;Direction;SourceAddress;SourceDNSName;SourcePort;DestinationAddress;DestinationDNSName;DestinationPort;Protocol;InterfaceIndex" | Out-File $FileName
    $Global:EventsArr | Out-File $FileName -Append
    start $FileName
 })

# toExcel
$Button_outExcel.add_Click.Invoke({
    Try{
        Get-ChildItem -Path "$env:TEMP\fwmon*.t*" | ForEach-Object {Remove-Item $_ -Force -ErrorAction SilentlyContinue}
        Get-ChildItem -Path "$env:TEMP\fwmon*.xlsx" | ForEach-Object {Remove-Item $_ -Force -ErrorAction SilentlyContinue}
        $FileName = "$env:TEMP\fwmon_" + (Get-Date).ToString("yyyyMMdd-HHmmss") + ".txt"
        "RecordID;Date;Time;ProcessID;ApplicationFullPath;FirewallRule#;Action;Direction;SourceAddress;SourceDNSName;SourcePort;DestinationAddress;DestinationDNSName;DestinationPort;Protocol;InterfaceIndex" | Out-File $FileName
        $SyncHash.Parent_EventsArr | Out-File $FileName -Append

        Write-Host $((Get-Date).ToString("yyyy/MM/dd HH:mm:ss")) -no ; Write-Host " Start converting data to Excel file" -ForegroundColor $MessagesColor
        $excelObject = New-Object -ComObject Excel.Application
        $Workbook = $excelObject.Workbooks.Add()
        $worksheet = $Workbook.Sheets.Item(1)
        $csvConnector = $worksheet.QueryTables.add($("TEXT;" + $FileName), $worksheet.Range("A1"))
        $query = $worksheet.QueryTables.item($csvConnector.name)
        $query.TextFileOtherDelimiter = ";"
        $query.AdjustColumnWidth = 1
        $query.Refresh()| Out-Null
        $query.Delete()
        Add-Type -AssemblyName "Microsoft.Office.Interop.Excel"
        $worksheet.Cells.EntireColumn.AutoFit()  | Out-Null
        $worksheet.Columns.AutoFit() | Out-Null
        $headerRange = $worksheet.Range("A1","P1")
        $headerRange.AutoFilter() | Out-Null
        $table = $excelObject.ActiveSheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $excelObject.ActiveCell.CurrentRegion, $null ,[Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes)
        $xlsxFile = $FileName.replace(".txt",".xlsx")
        $Workbook.SaveAs($xlsxFile, 51)
        $Workbook.Close()
        $excelObject.Quit()
        Write-Host $((Get-Date).ToString("yyyy/MM/dd HH:mm:ss")) -no ; Write-Host " Stop converting data to Excel file" -ForegroundColor $MessagesColor
        Write-Host $((Get-Date).ToString("yyyy/MM/dd HH:mm:ss")) -no ; Write-Host " Opening Excel file ..." -ForegroundColor $MessagesColor
        Start $xlsxFile
        Write-Host "`nWaiting for commands" -ForegroundColor $MessagesColor
    }
    catch {[System.Windows.MessageBox]::Show($_.Exception)}
})

# ButtonRules
$Button_FilterId.add_Click.Invoke({
    $filepath = "$env:TMP\filters.xml"
    If (Test-Path $filepath) {Remove-Item -Path $filepath -Force}
    $Arguments = "/c netsh wfp show filter file = " + $filepath
    Try {
        Start-Process -FilePath ($env:SystemRoot + "\System32\cmd.exe") -ArgumentList $Arguments -Verb runAs
        $Locked = $True
                                        Do {
        Start-Sleep -Milliseconds 100
        If (Test-Path $filepath) {
            try {
                [IO.File]::OpenWrite($filepath).close()
                $Locked = $False
            } catch {}
        }
    } While ($Locked)
    
        [System.Collections.ArrayList]$AllFilters = @()
        $Filters = Select-Xml -Path $filepath -XPath "/wfpdiag/filters/item"

                $Filters | % {
        $AllFilters += New-Object -Type PSObject -Prop @{ ‘FilterId’ = $_.Node.filterId ; ‘Name’ = $_.Node.DisplayData.Name ; ‘Description’ = $_.Node.DisplayData.Description ; ‘Action’ = $_.Node.Action.Type}
    }
        $AllFilters | Sort filterId | Select filterId,Name,Description,Action | Out-GridView -Title "All Filters"

        Remove-Item -Path $filepath -Force
    } catch {}
})

# ButtonExit
$Button_Exit.add_Click.Invoke({
    (get-host).UI.RawUI.WindowTitle = $initial_console_title
    Try {
        $Global:psCmd.EndStop($Global:psCmd.BeginStop($null,$Global:RunspaceHandle))
        Get-EventSubscriber | Remove-Event
        $Global:Watcher.Enabled = $False
    } catch {}

    Get-ChildItem -Path "$env:TEMP\fwmon*.t*" | ForEach-Object {Remove-Item $_ -Force -ErrorAction SilentlyContinue}
    Write-Host "`nGoodbye!"
    $Window_main.OwnedWindows | % {$_.Close()}
    $Window_main.Close()
    Exit
})

# Button_Hide
$Button_Hide.add_Click.Invoke({
    
    <#
    Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '

    $consolePtr = [Console.Window]::GetConsoleWindow()
    # Hide = 0,
    # ShowNormal = 1,
    # ShowMinimized = 2,
    # ShowMaximized = 3,
    # Maximize = 3,
    # ShowNormalNoActivate = 4,
    # Show = 5,
    # Minimize = 6,
    # ShowMinNoActivate = 7,
    # ShowNoActivate = 8,
    # Restore = 9,
    # ShowDefault = 10,
    # ForceMinimized = 11
    [Console.Window]::ShowWindow($consolePtr, 2) | Out-Null
    #>

    $Window_main.WindowState = "Minimized"
})

# ButtonSecPol
$ButtonSecPol.add_Click.Invoke({ Start-Process -FilePath ($env:SystemRoot+"\system32\mmc.exe") -ArgumentList $("$Env:SystemRoot\System32\secpol.msc") -Verb runAs })

# ButtonWF
$ButtonWF.add_Click.Invoke({
    Try {
        Start-Process -FilePath ($env:SystemRoot+"\system32\mmc.exe") -ArgumentList ($env:SystemRoot+"\system32\wf.msc") -Verb runAs
    } catch {}
})

# Button_Go
$Button_Go.add_Click.Invoke({
    Write-Host $((Get-Date).ToString("yyyy/MM/dd HH:mm:ss")) -no ; Write-Host " Start Events subscriber" -ForegroundColor $MessagesColor
    $Button_Go.IsEnabled = $false
    $Button_outTXT.IsEnabled = $true

    [System.Collections.ArrayList]$DNSServers = @()
    $DNSServers += (Get-DnsClientServerAddress).ServerAddresses
    $Global:EventsArr.Clear()

    if (-Not ($CheckBox_Past.IsChecked)) { # realtime monitor
        $Button_Stop.IsEnabled = $true
        $SyncHash.Parent_DNSServers = $DNSServers
        $Global:Watcher.Enabled = $true
    } else { # Past Events query
        $EndDateTime = Get-Date
        If ($PastEventsWindow_CheckBox_last.IsChecked) {
            $CheckedRadioButton = ($PastEventsWindow_StackPanel_Lower.Children | ? {$_.IsChecked}).Name
            Switch ($CheckedRadioButton) {
                "RadioButton_minutes" {$StartDateTime = $EndDateTime.AddMinutes(-([int]($PastEventsWindow_TextBox_last.Text)))}
                "RadioButton_hours" {$StartDateTime = $EndDateTime.AddHours(-([int]($PastEventsWindow_TextBox_last.Text)))}
                "RadioButton_days" {$StartDateTime = $EndDateTime.AddDays(-([int]($PastEventsWindow_TextBox_last.Text)))}
            }
        }
        else {
            $StartDateTime = Get-Date -Year $PastEventsWindow_TextBox_SY.Text -Month $PastEventsWindow_TextBox_SM.Text -Day $PastEventsWindow_TextBox_SD.Text -Hour $PastEventsWindow_TextBox_SH.Text -Minute $PastEventsWindow_TextBox_SMt.Text -Second $PastEventsWindow_TextBox_SS.Text
            $EndDateTime = Get-Date -Year $PastEventsWindow_TextBox_TY.Text -Month $PastEventsWindow_TextBox_TM.Text -Day $PastEventsWindow_TextBox_TD.Text -Hour $PastEventsWindow_TextBox_TH.Text -Minute $PastEventsWindow_TextBox_TMt.Text -Second $PastEventsWindow_TextBox_TS.Text
        }

        Write-Host "Reading event log" -ForegroundColor $MessagesColor
        [System.Collections.ArrayList]$EventsArr = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{
            LogName = "Security"
            Id = 5150,5152,5153,5156,5157
            StartTime = $StartDateTime
            EndTime = $EndDateTime
        }

        $matchArray = ($TextBox_MatchText.Text -split ",")
        $matchArrayPos = $matchArray.Where({ $_[0] -ne "!" })
        $tmpArrayNeg = $matchArray.where({ $_[0] -eq "!" })
        $matchArrayNeg = New-Object System.Collections.ArrayList($null) ; $tmpArrayNeg | % {$matchArrayNeg += $_.replace("!","")}
        $Protocols =  @{[UInt32]0 = "HOPOPT" ; [UInt32]1 = "ICMP" ; [UInt32]2 = "IGMP"; [UInt32]4 = "IP encapsulation" ; [UInt32]6 = "TCP"; [UInt32]17 = "UDP" ; [UInt32]58 = "IPv6-ICMP"}
        $FWActions = @{[int64]-9214364837600034816 = "Allow" ; [int64]-9218868437227405312 = "Deny"}
        $ActionsColor = @{[int64]-9214364837600034816 = "White" ; [int64]-9218868437227405312 = "DarkGray"}
        $FWDirections = @{"%%14593" = "OUT" ; "%%14592" = "IN"}
        $PrivateAddresses = '(^127\.)|(^192\.168\.)|(^169\.254\.)|(^10\.)|(^224\.)|(^240\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^::1$)|(^[fF][cCdD])|(2(?:2[4-9]|3\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d?|0)){3}$)|(255.255.255.255)'
        $EventsArr | % {
            $EventRecord = $_
            $appFullPath = $EventRecord.Properties[1].Value
            $appName = $appFullPath.Substring($appFullPath.LastIndexOf("\") + 1)
            if ($appName -eq "svchost.exe") {
                Try { $appName += "|$( $TasklistOut.Where({$_.Split(",")[1] -eq [string]$EventRecord.Properties[0].Value}).Split(",")[2] )" } catch {$appName += "|-"}
                $appFullPath += $appName.Substring(11)
            }
            $EventRecordXML = [xml]$EventRecord.ToXml()
            $outstr = @($( `
            $EventRecord.RecordID, `
            $EventRecord.TimeCreated.ToString("yyyy/MM/dd HH:mm:ss"), `
            [string]$EventRecord.Properties[0].Value, `
            $appFullPath, `
            $appname, `
            $("FilterId:" + ((($EventRecordXML).Event.EventData.Data.Where({$_.Name -eq "FilterRTID"})).'#text')), `
            $($FWActions.($EventRecord.Keywords)), `
            $($FWDirections.($EventRecord.Properties[2].Value)), `
            $EventRecord.Properties[3].Value, `
            $( ([object[]]($DNSCache.Where({$_.Data -eq $EventRecord.Properties[3].Value}))[0]).Name ), `
            $EventRecord.Properties[4].Value, `
            $EventRecord.Properties[5].Value, `

            $( ([object[]]($DNSCache.Where({$_.Data -eq $EventRecord.Properties[5].Value}))[0]).Name ), `
            $EventRecord.Properties[6].Value, `
            $($Protocols.$($EventRecord.Properties[7].Value)), `
            $((($EventRecordXML).Event.EventData.Data.Where({$_.Name -eq "InterfaceIndex"})).'#text') ))

            # Применение фильтров
            $EventFiltered = $false

            if ((-Not $CheckBox_IPv4.IsChecked) -and ($outstr[8].Indexof(":") -eq -1) -and ($outstr[11].Indexof(":") -eq -1)) {$EventFiltered = $true}
            if ((-Not $CheckBox_IPv6.IsChecked) -and ($outstr[8].Indexof(":") -ne -1) -and ($outstr[11].Indexof(":") -ne -1)) {$EventFiltered = $true}
            if ((-Not $CheckBox_DNS.IsChecked) -and ($DNSServers.IndexOf($outstr[11]) -ne -1) -and (($outstr[13] -eq "53") -or ($outstr[13] -eq "5353"))) {$EventFiltered = $true}
            if ((-Not $CheckBox_DHCP.IsChecked) -and ((($outstr[10] -eq "68") -and ($outstr[13] -eq "67")) -or (($outstr[8].Indexof(":") -ne -1) -and (($outstr[10] -eq "546") -or ($outstr[13] -eq "547")))) -and ($outstr[14] -eq "UDP")) {$EventFiltered = $true}
            
            $SourceIPIsPrivate = $outstr[8] -match $PrivateAddresses
            $DestIPIsPrivate = $outstr[11] -match $PrivateAddresses
            if (-Not $CheckBox_Other.IsChecked) {
                If ($SourceIPIsPrivate -and $DestIPIsPrivate) {$EventFiltered = $true}
            }
            if (-Not $CheckBox_Global.IsChecked) {
                If ((-Not $SourceIPIsPrivate) -or (-Not $DestIPIsPrivate)) {$EventFiltered = $true}
            }
                    
            if ($TextBox_MatchText.Text -ne "") {
                If ($matchArrayNeg.Count -ne 0) {
                    If ( ($matchArrayNeg.Where({ $outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15] -match $_ })).Count -gt 0 ) {
                        $EventFiltered = $true
                    }
                }
                If ($matchArrayPos.Count -ne 0) {
                    If ( ($matchArrayPos.Where({ $outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15] -match $_ })).Count -ne $matchArrayPos.Count ) {
                        $EventFiltered = $true
                    }
                }
            }

            If (-Not $EventFiltered) {
                $Global:EventsArr.Add($(@($outStr[0];[string[]]($outStr[1] -split " ");[string[]]$outStr[2,3,5,6,7,8,9,10,11,12,13,14,15]) -join ";"))

                #Out-Console
                $ForegroundMarkColor = "Yellow"
                if ($TextBox_MarkText.Text -eq "") {
                    Write-Host $($outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15]) -ForegroundColor $($ActionsColor.($EventRecord.Keywords))
                } else {
                    $markArray = ($TextBox_MarkText.Text -split ",")
                    If ( $markArray.Where({ $outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15] -match $_ }) ) {
                        ForEach ($element in $outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15]) {
                            If ( $markArray.Where({ $element -match $_ }) ) {$fColor = $ForegroundMarkColor} else {$fColor = $ActionsColor.($EventRecord.Keywords)}
                            Write-Host ($element + " ") -ForegroundColor $fColor -BackgroundColor "DarkGreen" -NoNewline
                        }
                        Write-Host
                    }
                    else {
                        Write-Host $($outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15]) -ForegroundColor $ActionsColor.($EventRecord.Keywords)
                    }
                }   
            }
        }

        $Button_Go.IsEnabled = $true
        Write-Host "Waiting for commands" -ForegroundColor $MessagesColor
    }
})

$Query = @"
<QueryList>
    <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=5150 or EventID=5152 or EventID=5153 or EventID=5156 or EventID=5157)]]</Select>
    </Query>
</QueryList>
"@

$subscriptionQuery = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new("Security",[System.Diagnostics.Eventing.Reader.PathType]::LogName,$Query)
[System.Diagnostics.Eventing.Reader.EventLogWatcher]$Global:Watcher = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new($subscriptionQuery)

# Thread for getting svchost instances to array $TasklistOut
[string[]]$TasklistOut = (Tasklist /svc /fo csv /nh /fi "imagename eq svchost.exe").Replace('"',"")
$SyncHash2 = [hashtable]::Synchronized(@{ Parent_TaskListOut = $TasklistOut ; Parent_Watcher = $Global:Watcher ; Parent_ConsoleHost = (Get-Host)})
$newRunspace2 =[runspacefactory]::CreateRunspace()
$newRunspace2.ApartmentState = "STA"
$newRunspace2.ThreadOptions = "Default"         
$newRunspace2.Open()
$newRunspace2.SessionStateProxy.SetVariable("SyncHash2",$SyncHash2)
$psCmd2 = [PowerShell]::Create()
$Hide2 = $psCmd2.AddScript({
    $queryParameters = '__InstanceCreationEvent', (New-Object TimeSpan 0,0,1), "TargetInstance isa 'Win32_Process'"
    $Query = New-Object System.Management.WqlEventQuery -ArgumentList $queryParameters
    $ProcessWatcher = New-Object System.Management.ManagementEventWatcher $Query
    $newEventArgs = @{
        SourceIdentifier = 'PowerShell.ProcessCreated'
        Sender = $Sender
        EventArguments = $EventArgs.NewEvent.TargetInstance
    }

    Register-ObjectEvent -InputObject $ProcessWatcher -EventName "EventArrived" -Action { 
        if ($SyncHash2.Parent_Watcher.Enabled -and ($EventArgs.NewEvent.TargetInstance.Description -eq "svchost.exe")) {
            $SyncHash2.Parent_TaskListOut = (Tasklist /svc /fo csv /nh /fi "imagename eq svchost.exe").Replace('"',"")
            #$SyncHash2.Parent_ConsoleHost.Ui.WriteLine("************************")
        }
    }

    $queryParameters2 = '__InstanceDeletionEvent', (New-Object TimeSpan 0,0,1), "TargetInstance isa 'Win32_Process'"
    $Query2 = New-Object System.Management.WqlEventQuery -ArgumentList $queryParameters2
    $ProcessWatcher2 = New-Object System.Management.ManagementEventWatcher $query2
    $newEventArgs2 = @{
        SourceIdentifier = 'PowerShell.ProcessCreated'
        Sender = $Sender
        EventArguments = $EventArgs.NewEvent.TargetInstance
    }

    Register-ObjectEvent -InputObject $ProcessWatcher2 -EventName "EventArrived" -Action {
        if ($SyncHash2.Parent_Watcher.Enabled -and ($EventArgs.NewEvent.TargetInstance.Description -eq "svchost.exe")) {
            $SyncHash2.Parent_TaskListOut = (Tasklist /svc /fo csv /nh /fi "imagename eq svchost.exe").Replace('"',"")
            #$SyncHash2.Parent_ConsoleHost.Ui.WriteLine("************************")
        }
    }
})
$psCmd2.Runspace = $newRunspace2
$RunspaceHandle2 = $psCmd2.BeginInvoke()

# Thread for getting DNS cache to array $DNSCache
$DNSCache = Try {Get-DnsClientCache -Type $("A","AAAA") -ea 0 | Select Name,Data} catch {}
$SyncHash3 = [hashtable]::Synchronized(@{ Parent_DNSCache = $DNSCache ; Parent_Watcher = $Global:Watcher })
$newRunspace3 =[runspacefactory]::CreateRunspace()
$newRunspace3.ApartmentState = "STA"
$newRunspace3.ThreadOptions = "Default"         
$newRunspace3.Open()
$newRunspace3.SessionStateProxy.SetVariable("SyncHash3",$SyncHash3)
$psCmd3 = [PowerShell]::Create()
$Hide3 = $psCmd3.AddScript({
    Do {
        if ($SyncHash3.Parent_Watcher.Enabled) { $SyncHash3.Parent_DNSCache = $(Try {Get-DnsClientCache -Type $("A","AAAA") -ea 0 | Select Name,Data} catch {}) | Select Name,Data } ; Start-Sleep 3
    } Until ($Something)
})
$psCmd3.Runspace = $newRunspace3
$RunspaceHandle3 = $psCmd3.BeginInvoke()

# Thread for catching Security Log Events
$SyncHash = [hashtable]::Synchronized(@{
    Parent_ConsoleHost = (Get-Host)
    Parent_Window_main = $Window_main
    MessagesColor = $MessagesColor
    Parent_Button_outTXT = $Button_outTXT
    Parent_CheckBox_IPv4_IsChecked = $CheckBox_IPv4.IsChecked
    Parent_CheckBox_IPv6_IsChecked = $CheckBox_IPv6.IsChecked
    Parent_CheckBox_DNS_IsChecked = $CheckBox_DNS.IsChecked
    Parent_CheckBox_DHCP_IsChecked = $CheckBox_DHCP.IsChecked
    Parent_CheckBox_Local_IsChecked = $CheckBox_Local.IsChecked
    Parent_CheckBox_Other_IsChecked = $CheckBox_Other.IsChecked
    Parent_CheckBox_Global_IsChecked = $CheckBox_Global.IsChecked
    Parent_TextBox_MarkText_Text = $TextBox_MarkText.Text
    Parent_TextBox_MatchText_Text = $TextBox_MatchText.Text
    Parent_MessagesColor = $MessagesColor
    Parent_Watcher = $Global:Watcher
    Parent_EventsArr = $Global:EventsArr
    Parent_Tasklist = $TasklistOut
    Parent_DNSServers = $DNSServers
    Parent_DNSCache = $DNSCache
    Parent_EventsArrMaxLength = $Global:EventsArrMaxLength
    Parent_Protocols =  @{[UInt32]0 = "HOPOPT" ; [UInt32]1 = "ICMP" ; [UInt32]2 = "IGMP"; [UInt32]4 = "IP encapsulation" ; [UInt32]6 = "TCP"; [UInt32]17 = "UDP" ; [UInt32]58 = "IPv6-ICMP"}
    Parent_FWActions = @{[int64]-9214364837600034816 = "Allow" ; [int64]-9218868437227405312 = "Deny"}
    Parent_ActionsColor = @{[int64]-9214364837600034816 = "White" ; [int64]-9218868437227405312 = "DarkGray"}
    Parent_FWDirections = @{"%%14593" = "OUT" ; "%%14592" = "IN"}
    Parent_PrivateAddresses = '(^127\.)|(^192\.168\.)|(^169\.254\.)|(^10\.)|(^224\.)|(^240\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^::1$)|(^[fF][cCdD])|(2(?:2[4-9]|3\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d?|0)){3}$)|(255.255.255.255)'
})

$Global:newRunspace =[runspacefactory]::CreateRunspace()
$Global:newRunspace.ApartmentState = "STA"
$Global:newRunspace.ThreadOptions = "Default"         
$Global:newRunspace.Open()
$Global:newRunspace.SessionStateProxy.SetVariable("SyncHash",$SyncHash)
$Global:psCmd = [PowerShell]::Create()
$Hide = $Global:psCmd.AddScript({
    <#
    00 RecordID
    01 TimeCreated
    02 ProcessID
    03 appFullPath
    04 appname
    05 FilterRTID
    06 Action
    07 Direction
    08 SourceAddress
    09 SourceName
    10 SourcePort
    11 DestAddress
    12 DestName
    13 Destport
    14 Protocol
    15 InterfaceIndex
    #>

    Register-ObjectEvent -InputObject $SyncHash.Parent_Watcher -EventName "EventRecordWritten" -Action {
        if ($SyncHash.Parent_Watcher.Enabled) {
            $StartDateTime = $(Get-Date)
            Try {
                $EventRecord = $EventArgs.EventRecord
                $EventRecordXML = [xml]$EventRecord.ToXml()
                $matchArray = ($SyncHash.Parent_TextBox_MatchText_Text -split ",")
                $matchArrayPos = $matchArray.Where({ $_[0] -ne "!" })
                $tmpArrayNeg = $matchArray.where({ $_[0] -eq "!" })
                $matchArrayNeg = New-Object System.Collections.ArrayList($null) ; $tmpArrayNeg | % {$matchArrayNeg += $_.replace("!","")}
                $appFullPath = $EventRecord.Properties[1].Value
                $appName = $appFullPath.Substring($appFullPath.LastIndexOf("\") + 1)
                if ($appName -eq "svchost.exe") {
                    Try { $appName += "|$( $SyncHash.Parent_Tasklist.Where({$_.Split(",")[1] -eq [string]$EventRecord.Properties[0].Value}).Split(",")[2] )" } catch {$appName += "|-"}
                    $appFullPath += $appName.Substring(11)
                }

                $outstr = @($( `
                $EventRecord.RecordID, `
                $EventRecord.TimeCreated.ToString("yyyy/MM/dd HH:mm:ss"), `
                [string]$EventRecord.Properties[0].Value, `
                $appFullPath, `
                $appname, `
                $("FilterId:" + ((($EventRecordXML).Event.EventData.Data.Where({$_.Name -eq "FilterRTID"})).'#text')), `
                $($SyncHash.Parent_FWActions.($EventRecord.Keywords)), `
                $($SyncHash.Parent_FWDirections.($EventRecord.Properties[2].Value)), `
                $EventRecord.Properties[3].Value, `
                $( ([object[]]($SyncHash.Parent_DNSCache.Where({$_.Data -eq $EventRecord.Properties[3].Value}))[0]).Name ), `
                $EventRecord.Properties[4].Value, `
                $EventRecord.Properties[5].Value, `
                $( ([object[]]($SyncHash.Parent_DNSCache.Where({$_.Data -eq $EventRecord.Properties[5].Value}))[0]).Name ), `
                $EventRecord.Properties[6].Value, `
                $($SyncHash.Parent_Protocols.$($EventRecord.Properties[7].Value)), `
                $((($EventRecordXML).Event.EventData.Data.Where({$_.Name -eq "InterfaceIndex"})).'#text') ))

                # Применение фильтров
                $EventFiltered = $false

                if ((-Not $SyncHash.Parent_CheckBox_IPv4_IsChecked) -and ($outstr[8].Indexof(":") -eq -1) -and ($outstr[11].Indexof(":") -eq -1)) {$EventFiltered = $true}
                if ((-Not $SyncHash.Parent_CheckBox_IPv6_IsChecked) -and ($outstr[8].Indexof(":") -ne -1) -and ($outstr[11].Indexof(":") -ne -1)) {$EventFiltered = $true}
                if ((-Not $SyncHash.Parent_CheckBox_DNS_IsChecked) -and ($SyncHash.Parent_DNSServers.IndexOf($outstr[11]) -ne -1) -and (($outstr[13] -eq "53") -or ($outstr[13] -eq "5353"))) {$EventFiltered = $true}
                if ((-Not $SyncHash.Parent_CheckBox_DHCP_IsChecked) -and ((($outstr[10] -eq "68") -and ($outstr[13] -eq "67")) -or (($outstr[8].Indexof(":") -ne -1) -and (($outstr[10] -eq "546") -or ($outstr[13] -eq "547")))) -and ($outstr[14] -eq "UDP")) {$EventFiltered = $true}
            
                $SourceIPIsPrivate = $outstr[8] -match $SyncHash.Parent_PrivateAddresses
                $DestIPIsPrivate = $outstr[11] -match $SyncHash.Parent_PrivateAddresses
                if (-Not $SyncHash.Parent_CheckBox_Other_IsChecked) {
                    If ($SourceIPIsPrivate -and $DestIPIsPrivate) {$EventFiltered = $true}
                }
                if (-Not $SyncHash.Parent_CheckBox_Global_IsChecked) {
                    If ((-Not $SourceIPIsPrivate) -or (-Not $DestIPIsPrivate)) {$EventFiltered = $true}
                }
                    
                if ($SyncHash.Parent_TextBox_MatchText_Text -ne "") {
                    If ($matchArrayNeg.Count -ne 0) {
                        If ( ($matchArrayNeg.Where({ $outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15] -match $_ })).Count -gt 0 ) {
                            $EventFiltered = $true
                        }
                    }
                    If ($matchArrayPos.Count -ne 0) {
                        If ( ($matchArrayPos.Where({ $outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15] -match $_ })).Count -ne $matchArrayPos.Count ) {
                            $EventFiltered = $true
                        }
                    }
                }

                #$SyncHash.Parent_ConsoleHost.Ui.WriteLine($($SyncHash.Parent_EventsArr.Count))
                If (-Not $EventFiltered) {
                    # Out-Array
                    if ($SyncHash.Parent_EventsArrMaxLength -ne 0) {
                        If ($SyncHash.Parent_EventsArr.Count -gt $SyncHash.Parent_EventsArrMaxLength) { $SyncHash.Parent_EventsArr.RemoveRange(0,($SyncHash.Parent_EventsArr.Count - $SyncHash.Parent_EventsArrMaxLength)) }
                        If ($SyncHash.Parent_EventsArr.Count -eq $SyncHash.Parent_EventsArrMaxLength) { $SyncHash.Parent_EventsArr.RemoveAt(0) }
                    }
                    $SyncHash.Parent_EventsArr.Add($(@($outStr[0];[string[]]($outStr[1] -split " ");[string[]]$outStr[2,3,5,6,7,8,9,10,11,12,13,14,15]) -join ";"))
                

                    #Out-Console
                    $BackgroundColor = $SyncHash.Parent_ConsoleHost.UI.RawUI.BackgroundColor
                    $ForegroundMarkColor = "Yellow"

                    if ($SyncHash.Parent_TextBox_MarkText_Text -eq "") {
                        $SyncHash.Parent_ConsoleHost.Ui.WriteLine($($SyncHash.Parent_ActionsColor.($EventRecord.Keywords)),$BackgroundColor,$($outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15]))
                    } else {
                        $markArray = ($SyncHash.Parent_TextBox_MarkText_Text -split ",")
                        $bColor = $BackgroundColor
                        If ( $markArray.Where({ $outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15] -match $_ }) ) {
                            $bColor = "DarkGreen"
                            ForEach ($element in $outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15]) {
                                If ( $markArray.Where({ $element -match $_ }) ) {$fColor = $ForegroundMarkColor} else {$fColor = $($SyncHash.Parent_ActionsColor.($EventRecord.Keywords))}
                                $SyncHash.Parent_ConsoleHost.Ui.Write($fColor,$bColor,($element + " "))
                            }
                            $SyncHash.Parent_ConsoleHost.Ui.WriteLine()
                        }
                        else {
                            $SyncHash.Parent_ConsoleHost.Ui.WriteLine($($SyncHash.Parent_ActionsColor.($EventRecord.Keywords)),$BackgroundColor,$($outstr[1,2,4,5,6,7,8,9,10,11,12,13,14,15]))
                        }
                    }   
                }

            #$SyncHash.Parent_ConsoleHost.Ui.WriteLine($((New-TimeSpan -Start $StartDateTime -End (Get-Date)).TotalMilliseconds))
            } catch {$SyncHash.Parent_ConsoleHost.Ui.WriteLine(@($_.InvocationInfo.PositionMessage))}
        }
    }

})
$Global:psCmd.Runspace = $Global:newRunspace
$Global:RunspaceHandle = $Global:psCmd.BeginInvoke()

$Window_main.Add_Loaded({
    $Window_main.Title += $applicationName + " v." + $applicationVersion
    $ConsoleWindow = Get-Window $ConsoleHandle
    $Window_main.Left = $ConsoleWindow.Left
    $Window_main.Top = $ConsoleWindow.Top - $Window_main.Height
    $Window_Main_TextBox_Buffer.Text = $Global:EventsArrMaxLength
})
$Window_main.Activate() | Out-Null
$Window_main.Focus() | Out-Null
Write-Host "`nWaiting for commands" -ForegroundColor $MessagesColor
$Window_main.ShowDialog() | Out-Null