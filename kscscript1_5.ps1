
#
# 0. parsing config file
#

$configfile = Get-Content .\config.ini -encoding utf8

# regexp for connecting parameters
$LDAPServer = $configfile | Select-String "(server:)"
$LDAPServer = $LDAPServer.ToString().Replace("server: ", "")

$dc1 = $configfile | Select-String "(dc1:)"
$dc1 = $dc1.ToString().Replace("dc1: ", "")

$dc2 = $configfile | Select-String "(dc2:)"
$dc2 = $dc2.ToString().Replace("dc2: ", "")

$trace = $configfile | Select-String "(trace:)"
$trace = $trace.ToString().Replace("trace: ", "")

# parsing exclusion groups and building correct querry with its names
$exclgroups = $configfile | Select-String "(exclgroup:)"

# this var for adding to result querry
$resultgroups = ""
# every excluded group should be mentioned in the querry
foreach ($group in $exclgroups)
{
    $group = $group.ToString().Replace("exclgroup: ", "")
    $group = "(!(memberof=" + $group + "))"

    # concatinating all groups together
    $resultgroups += $group
}


$searchpaths = $configfile | Select-String "(path:)"


# get script location
$loc =  Get-Location
$locstr = $loc.ToString()

# creating log file
if($trace -eq "1") {$LogFile = New-Item -Path ($locstr + "\log.txt") -Force -ItemType File}




#
# 0. GUI
#

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'KSC Script'
$form.Size = New-Object System.Drawing.Size(460,400)
$form.StartPosition = 'CenterScreen'

# OK button
$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(145,320)
$OKButton.Size = New-Object System.Drawing.Size(75,23)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
#$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

# Cancel button
$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(220,320)
$CancelButton.Size = New-Object System.Drawing.Size(75,23)
$CancelButton.Text = 'Cancel'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)

# logon name
$logonlabel = New-Object System.Windows.Forms.Label
$logonlabel.Location = New-Object System.Drawing.Point(10,20)
$logonlabel.Size = New-Object System.Drawing.Size(200,20)
$logonlabel.Text = 'Login:'
$form.Controls.Add($logonlabel)

$logonBox = New-Object System.Windows.Forms.TextBox
$logonBox.Location = New-Object System.Drawing.Point(10,40)
$logonBox.Size = New-Object System.Drawing.Size(200,20)
$form.Controls.Add($logonBox)

# pass
$passlabel = New-Object System.Windows.Forms.Label
$passlabel.Location = New-Object System.Drawing.Point(230,20)
$passlabel.Size = New-Object System.Drawing.Size(200,20)
$passlabel.Text = 'Password:'
$form.Controls.Add($passlabel)

$passBox = New-Object System.Windows.Forms.TextBox
$passBox.PasswordChar = '*'
$passBox.Location = New-Object System.Drawing.Point(230,40)
$passBox.Size = New-Object System.Drawing.Size(200,20)
$form.Controls.Add($passBox)

#search paths
$SPlabel = New-Object System.Windows.Forms.Label
$SPlabel.Location = New-Object System.Drawing.Point(10,80)
$SPlabel.Size = New-Object System.Drawing.Size(200,20)
$SPlabel.Text = 'Search paths:'
$form.Controls.Add($SPlabel)

$SPBox = New-Object System.Windows.Forms.TextBox
$SPBox.Location = New-Object System.Drawing.Point(10,100)
$SPBox.Size = New-Object System.Drawing.Size(420,200)
$SPBox.Multiline = 1

foreach ($path in $searchpaths)
{
    $path = $path.ToString().Replace("path: ", "")
    $SPBox.Text += $path
    $SPBox.Text += "`r`n"
}

$form.Controls.Add($SPBox)




$form.Topmost = $true

$form.Add_Shown({$logonBox.Select()})
$result = $form.ShowDialog()

# if cancel button - stop the program
if ($result -eq [System.Windows.Forms.DialogResult]::Cancel){exit}

$login = $logonBox.Text
$pass = $passBox.Text





#
# 1. parsing domain computers list
# 

###   tracing   ###
if($trace -eq "1") {"ldap queries sequence:" >> $LogFile}


[System.Array[]]$list = @()

foreach ($path in $searchpaths)
{
    $path = $path.ToString().Replace("path: ", "")


    # ldap querry for each new container/OU
    $querry = "LDAP://" + $LDAPServer + ":389/" + $path + ",dc=" + $dc1 + ",dc=" + $dc2

    ###   tracing   ###
    if($trace -eq "1") {$querry >> $LogFile}

    # implementing ldap querry
    $dn = New-Object System.DirectoryServices.DirectoryEntry ($querry,$login,$pass)

    # Here look for a computer
    $ldapsearch = new-object System.DirectoryServices.DirectorySearcher($dn)
    $ldapsearch.filter = "(&(operatingsystem=*Windows Server*)(!userAccountControl:1.2.840.113556.1.4.803:=2)" + $resultgroups + ")"
    #$ldapsearch.filter = "(&(operatingsystem=*Windows Server*)" + $resultgroups + ")"


    $ldapsearch.SearchScope = "subtree"

    $list += $ldapsearch.FindAll()
}

###   tracing   ###
if($trace -eq "1") {"`r`nraw ldap search filter:" >> $LogFile; $ldapsearch.filter >> $LogFile}




#
# 2. parsing kaspersky query data to string array
#

# initialising result array
[System.String[]]$k = @()

# searching all html files in script location
$files = [IO.Directory]::EnumerateFiles($loc,'*.html','AllDirectories') 

###   tracing   ###
if($trace -eq "1") {"`r`ndetected html-file list:" >> $LogFile; $files >> $LogFile}

foreach ($file in $files)
{
    # parsing html code
    $html = Get-Content $file -encoding utf8

    # regexp for computers in kaspersky query html code
    $html = $html | Select-String "(<td class=`"sD`">|<td class=`"sDo`">)[a-zA-Zа-яА-Я0-9_\-`~]+<\/td>"

    # removing html tags
    for ($i=0; $i -lt $html.Count; $i++)
    {
        $a = $html[$i].ToString()

        $a = $a.Replace("<td class=`"sD`">", "")
        $a = $a.Replace("<td class=`"sDo`">", "")
        $a = $a.Replace("</td>", "")
        
        # add computer name to result
        $k += $a
    }
}




#
# if computer name from domain is not found in kaspersky list -> add it to result
#

# creating result file
$ResultFile = New-Item -Path ($locstr + "\result.csv") -Force -ItemType File

$var = 0

# every computer in domain list searching in kaspersky array
foreach ($comp in $list)
{
    foreach ($item in $k)
    {
        if ($item -eq $comp.Properties.name){$var = 1}
        
    }

    # formating csv string for every system
    if ($var -eq 0)
    {
        $entry = ""
        $entry += $comp.Properties.name.trim() + ";"
        $entry += [datetime]::FromFileTime($($comp.Properties.lastlogontimestamp)).ToString("d MMMM yyyy") + ";"
        $entry += $comp.Properties.operatingsystem.trim() + ";"
        $entry |  Out-File $ResultFile -Encoding UTF8 -Append

        #$comp.properties.useraccountcontrol
    }

    $var = 0
}
