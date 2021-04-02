param(
    [string]$targetConfig
)

<#	
	.NOTES
	===========================================================================
	 Created with: 	PowerShell v7.0.1
	===========================================================================

#>


[System.Console]::Clear()

# Check PowerCli and set to ignore certificate verifications if not already configured
If (Get-PowerCLIConfiguration -Scope Session | Where-Object {$_.InvalidCertificateAction -ne "Ignore"})
{
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
}

##----------------------------------------##
##          Terminal Settings             ##
##----------------------------------------##

#Configure initial window size and title
$pshost                   = get-host
$pswindow                 = $pshost.ui.rawui
$pswindow.windowtitle     = "VMware/Powershell Execution"
$pswindow.foregroundcolor = "White"
$pswindow.backgroundcolor = "Black"
# $newsize                  = $pswindow.windowsize
# $newsize.height           = 50
# $newsize.width            = 150
# $pswindow.windowsize      = $newsize


##----------------------------------------##
##                Globals                 ##
##----------------------------------------##

#Suppress all "warning" messages
$warningPreference        = "SilentlyContinue"

#$dateFormat               = Get-Date -Format yyyy_d_M
#$basicClr                 = "white"
#$stdMsgClr                = "DarkGray"
$actionClr                = "blue"
$errClr                   = "red"
$successClr               = "green"
$waitMsgClr               = "magenta"
#$powerStateClr            = "DarkRed"
$WWLabelBackClr           = "yellow"
#$WWLabelForeClr           = "black"
$menuItemClr              = "gray"

# target variable for configuration JSON file
$location = "" 
if ($targetConfig)
{
    $location = $targetConfig
}
else
{
    $location = 'lab'
}

Write-Host ""
Write-Host "-----------------------------------------------------------------" -ForegroundColor "${successClr}"
Write-Host "Script targeted to run on '${location}'"
Write-Host "-----------------------------------------------------------------" -ForegroundColor "${successClr}"
Write-Host ""

# Set current working directoy of running script location
$current_dir = $PSScriptRoot

# Check if config file exists and exit if not present
Try 
{
    # Check config for file
    Get-Content -Raw -Path "${current_dir}\config\${location}_config.json" -ErrorAction Stop | Out-Null
}
Catch 
{
    # Display Error Message
    Write-Host "-----------------------------------------------------------------" -ForegroundColor "${errClr}"
    Write-Host "Could not find the config file '${location}_config.json'!" -ForegroundColor "${errClr}"
    Write-Host "" 
    Write-Host "Please ensure it is placed in the correct directory '${current_dir}\config'." -ForegroundColor "${errClr}"
    Write-Host "-----------------------------------------------------------------" -ForegroundColor "${errClr}"
    Write-Host ""

    # Prompt user to enter any key to exit
    Write-Host -NoNewline "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

    # Exit Application
    Exit
}

# Create JSON object from target config file
$jsonObj = Get-Content -Raw -Path "${current_dir}\config\${location}_config.json" | ConvertFrom-Json

# $jsonObj | ConvertTo-Json

# Convert JSON object elements into specific hash object variables
$machines = $jsonObj.Machines
$esxis = $jsonObj.Esxis
$target_exec = $jsonObj.Applications

# Allocation of credentials for ESXi Hosts into a hash object $esxi_cred. Convert stored password from Base64 encoded within config JSON Object.
$esxi_cred = @{
    username=$jsonObj.EsxiCredentials.username; 
    password=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($jsonObj.EsxiCredentials.password))
}

# Allocation of vCenter IP Address and credentials for hash object $vCenter. Convert stored password from Base64 encoded within config JSON Object.
$vCenter = @{
    IP=$jsonObj.VCenter.IP
    username=$jsonObj.VCenter.username; 
    password=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($jsonObj.VCenter.password))
}

# Allocation of $cred Windows object to store credentials form Windows Remote Management Sessions
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $jsonObj.WindowsCredentials.username, (ConvertTo-SecureString -AsPlainText ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($jsonObj.WindowsCredentials.password))) -Force)

##----------------------------------------##
##               Functions                ##
##----------------------------------------##

# Job Scriptblock to poll endpoint webaddress and check readiness.
$job_status = {
    # Parameter IP of target machine
    param($ip)
    
    # Variable to update when check has succeeded and target responds to request
    $complete = $false
    
    # Beginning of do-while loop
    Do
    {
        # Beginning of try-catch loop. Allow us to supress unneccesary error codes given by Invoke-WebRequest operations when target machine entered an operational state
        Try
        {
            # Invoke web request to check webserver service is operational and accepting requests
            $Response = Invoke-WebRequest -Uri "https://${ip}" -SkipCertificateCheck -TimeoutSec 5 -ErrorAction SilentlyContinue
            # Check the status code of the response if equals 200 (Success)
            If($Response.StatusCode -eq "200")
            {
                # Update variable as $true to exit do-while loop
                $complete = $true
            }
            Else 
            { 
                # Do Nothing 
            }
        }
        Catch 
        {
            # Supress Exception Error Codes
            $_.Exception.Response.StatusCode.Value__ | Out-Null
            
            # Sleep for 10 Seconds on Error
            Start-Sleep -Seconds 10
        }
    } While($complete -eq $false)
}

# Function to check specific applications are running per machine
Function checkPrograms($machine)
{
    # Display message of process checking section for target virtual machine
    Write-Host "Checking that the necessary applications have started on $($machine.Name)" -ForegroundColor "${actionClr}"
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
    Write-Host ""
    
    # Create a PSSession
    $session = New-PSSession -ComputerName $machine.IP.default -Credential $cred -ErrorAction SilentlyContinue

    # For Each application 
    foreach ($exec in $target_exec)
    {  
        # If Application is necessary to be running on  target virtual machine
        If ($exec.Tag[0] -Contains $machine.Tag[0])
        {
            # Display start of process checks section
            Write-Host "Checking that $($exec.ServiceName) has started..." -ForegroundColor "${actionClr}"

            #Invoke-Command -ComputerName $machine.IP.default -Credential $cred -ScriptBlock {Start-Process -FilePath $Using:exec.ServiceExec -WorkingDirectory $Using:exec.Path}    
            $result = Invoke-Command -Session $session -ScriptBlock {Get-Process -Name $Using:exec.ServiceName} -ErrorAction SilentlyContinue
            If($result)
            {
                # Display that the process is running
                Write-Host "$($exec.Name) running!" -ForegroundColor "${successClr}"
                Write-Host ""
            }
            Else 
            {
                # Display that the process is not running
                Write-Host "$($exec.Name) not running!" -ForegroundColor "${errClr}"
                Write-Host ""  
            }
        }
    }
    # Remove all PSSessions
    Exit-PSSession
}

# Function to check the state of VMware Tools and Windows Remote Management services (GuestOS is operational)
Function checkToolsAndOS($machine)
{
    # Display enter VMware Toools and Windows Remote Management service check
    Write-Host "Waiting until VMware Tools and OS is running on $($machine.Name)..." -ForegroundColor "${actionClr}"
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"

    # Get details for target VM
    $vm = Get-Inventory -Name $machine.Name

    # While loop to wait for running state of VMware tools
    While ((Get-View -id $vm.Id).Guest.ToolsRunningStatus -ne "guestToolsRunning" ) 
    {
        # Do Nothing
    }
    
    # Display VMware Tools is running
    Write-Host "VMware Tools is running!" -ForegroundColor "${successClr}"
    Write-Host " "

    # While loop that waits until VMWare Tools is running before continuing
    While ((Get-View -id $vm.Id).Guest.GuestOperationsReady -ne "False")
    {
        # Do Nothing
    } 
    
    # Display Guest Operating System is running
    Write-Host "Guest Operating System is running!" -ForegroundColor "${successClr}"
    Write-Host " "

    # Save PSSession return object from function
    defaultNetworking($machine) 

    # Display message that Windows Remote Management services are now available
    Write-Host "Windows Remote Management services are available!" -ForegroundColor "${successClr}"
    Write-Host " "
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
}

# Function to check host allocation and migrates to the correct host when necessary
Function hostCorrection($machine)
{
    # Display entering host allocation check
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
    Write-Host "Checking host allocation for VM..." -ForegroundColor "${actionClr}"
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"

    #Get VM attributes
    $vm = Get-Inventory -Name $machine.Name
    $vm_spec = Get-View -id $vm.Id
    
    $vm_spec.Runtime.Host
    $machine.Host
    Write-host  ""

    # Compare host allocation actual to necessary configuration
    If ($vm_spec.Runtime.Host -ne (Get-Inventory | Where-Object {$_.Name -eq $machine.Host}).Id)
    {
        # Display VM not on correct host and action item
        Write-Host "Not correct Host for $($machine.Name), migrating to host at IP: $($machine.Host)" -ForegroundColor "${waitMsgClr}"

        # Create migration objects
        $migration_spec = New-Object VMware.Vim.VirtualMachineRelocateSpec
        $migration_spec.Host = New-Object VMware.Vim.ManagedObjectReference(Get-Inventory | Where-Object {$_.Name -eq $machine.Host}).Id
        
        # Start migration task
        $task = $vm_spec.RelocateVM_Task($migration_spec, $null)

        # Display task
        Write-Host $task -ForegroundColor "${WWLabelBackClr}"
        
        # While loop to check progress and exit on completion of migration
        While((Get-Task -Id $task).State -ne "Success")
        {
            #Do Nothing
        }
        
        # Display VM migration to target ESXi host complete
        Write-Host "Migration Complete!" -ForegroundColor "${successClr}"
        Write-Host " "
    }
    Else 
    {
        # Display VM is on the correctly configured ESXi Host
       Write-Host "$($machine.Name) is already on the correct host! Nothing to do!" -ForegroundColor "${successClr}"
       Write-Host " " 
    }
    # Display divider line within output to console
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
}

# Function to start Virtual Machine
Function startVM($machine)
{
    # Display enter starting VM operations
    Write-Host "Starting VM: $($machine.Name)..." -ForegroundColor "${actionClr}"
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
    
    # Get VM State
    $vm = Get-Inventory -Name $machine.Name
    $vm_spec = Get-View -Id $vm.Id

    # Ensure VM is powered off
    If ($vm_spec.Runtime.PowerState -eq "poweredOff")
    {
        # Start VM
        VMware.VimAutomation.Core\Start-VM -VM $machine.Name -Confirm:$false
        
        # While loop to wait until VM is running
        while($vm_spec.Runtime.PowerState -ne "PoweredOff")
        {
            #Do Nothing
        }
        
        # Display message when VM is running
        Write-Host "VM is now powered on!" -ForegroundColor "${successClr}"
        Write-Host " "
    }
    Else 
    {
        # Display VM is already running
        Write-Host "Virtual machine is already running. Nothing to do!" -ForegroundColor "${successClr}"
        Write-Host " "
    }

    # Display divider line within output to console
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
}

# Function to check default networking is operational
Function defaultNetworking($machine)
{
    # Display enter default network check
    Write-Host "Default network check..." -ForegroundColor "${actionClr}"
    
    # Get VM details
    $vm = Get-Inventory -Name $machine.Name
    $vm_spec = Get-View -Id $vm.Id

    # Get only default network adapter
    $target = ((Get-NetworkAdapter -VM $machine.Name) | Where-Object {$_.NetworkName -eq "Default"})

    # Loop though all devices configured for VM
    Foreach ($device in $vm_spec.Config.Hardware.Device)
    {
        # Loop to verify only network adapters
        If ($device.MacAddress -eq $target.MacAddress)
        {
            # Test device is connnected to VM within VMware vCenter
            If ($device.Connectable.Connected -eq "True")
            { 
                # Return session object
                return serviceTest($machine)
            }
            Else 
            {
                # Function call to reconnect network device within vCenter
                connectNetInterface -machine $machine -device $device -port $target
                
                # Sleep for 1 second
                Start-Sleep -Seconds 1

                # Return session object
                return serviceTest($machine)
            }
        }
    }
}

Function checkNetworking($machine)
{
    # Display checking networking for target VM
    Write-Host "Checking Networking for $($machine.Name) VM..." -ForegroundColor "${actionClr}"
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
    
    # Create session for target VM
    $session = New-PSSession -ComputerName $machine.IP.default -Credential $cred
    
    # Get VM details
    $vm = Get-Inventory -Name $machine.Name
    $vm_spec = Get-View -Id $vm.Id

    # Loop though all devices configured for VM
    Foreach ($device in $vm_spec.Config.Hardware.Device)
    {
        # Get only configured network adapters
        $configured_networks = (Get-NetworkAdapter -VM $machine.Name)
        # Loop to verify only network adapters
        Foreach($port in $configured_networks)
        {
            # Match device
            If ($port.MacAddress -eq $device.MacAddress)
            {
                # Display port network name
                Write-Host $port.NetworkName -ForegroundColor "${successClr}"
                
                # Check connection state of network adapter in VMware vCenter
                If ($device.Connectable.Connected -eq "True")
                {
                    # Display network adapter is connected
                    Write-Host "$($device.MacAddress) is connected!" -ForegroundColor "${successClr}"
                    # Test network function call
                    netTest -machine $machine -port $port -vm_spec $vm_spec -session $session
                }
                Else 
                {
                    # Connect network interface in VMware vCenter function call
                    connectNetInterface -machine $machine -device $device -port $port
                    # Verify adapter connected function call
                    adapterConnected -vm_spec $vm_spec -port $port -session $session
                    # Test network function call
                    netTest -machine $machine -port $port -vm_spec $vm_spec -session $session
                }
            }
        }
    }
    
    # Remove PSSession
    Remove-PSSession -Session $session
    # Display divider line within output to console
    Write-Host "--------------------------------------------------------------------------------"
}

# Funtion to check WSMan and PSSessions are operational
Function serviceTest($machine)
{
    # Ping configured IP Address
    If(Test-Connection $machine.IP.default -Count 1 -Quiet)
    {
        # Set test variable
        $wsman_test = $false

        # While loop to check WSMan is running
        While($wsman_test -eq $false)
        {
            # Check to verify WSMan is running
            If(Test-WSMan -ComputerName $machine.IP.default -ErrorAction SilentlyContinue)
            {
                $wsman_test = $true
            }
            Else 
            {
                # Nothing to update
            }
        }

        $session = $null
        While(!$session)
        {
            $session = New-PSSession -ComputerName $machine.IP.default -Credential $cred -ErrorAction SilentlyContinue 
            Start-Sleep -Seconds 3
        }
        # Return $session
        return $session | Out-Null
    }
    Else 
    {
        Write-Host "Session not created" -ForegroundColor "${errClr}"
        # Return $null
        return $null
    }    
}

# Function to connect target network adapter within VMware vCenter
Function connectNetInterface($machine, $device, $port)
{
    # Get VM details
    $vm = Get-Inventory -Name $machine.Name
    $vm_spec = Get-View -Id $vm.Id

    # Create new object for task to reconnect network interface in VMware vCenter
    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.DeviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec[] (1)
    $spec.DeviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec
    
    # Get correct object for Network Adapter Type
    $adapter_type = ((VMware.VimAutomation.Core\Get-VM -Name $machine.Name | Get-NetworkAdapter) | Where-Object {$_.NetworkName -eq $port.NetworkName}).Type
    
    # Set device object with correct adapter type (found differing configuration based on Physical Machine to VM import using VMware Standalone Converter)
    If($adapter_type -eq "e1000e")
    {
        $spec.DeviceChange[0].Device = New-Object VMware.Vim.VirtualE1000e
    }
    ElseIf($adapter_type -eq "e1000")
    {
        $spec.DeviceChange[0].Device = New-Object VMware.Vim.VirtualE1000
    }
    ElseIf($adapter_type -eq "Vmxnet3")
    {
        $spec.DeviceChange[0].Device = New-Object VMware.Vim.VirtualVmxnet3
    }
    
    # Continuation of obect creation/settings
    $spec.DeviceChange[0].Device.MacAddress = $device.MacAddress
    $spec.DeviceChange[0].Device.ResourceAllocation = New-Object VMware.Vim.VirtualEthernetCardResourceAllocation
    $spec.DeviceChange[0].Device.ResourceAllocation.Limit = $device.ResourceAllocation.Limit
    $spec.DeviceChange[0].Device.ResourceAllocation.Reservation = $device.ResourceAllocation.Reservation
    $spec.DeviceChange[0].Device.ResourceAllocation.Share = New-Object VMware.Vim.SharesInfo
    $spec.DeviceChange[0].Device.ResourceAllocation.Share.Shares = $device.ResourceAllocation.Share.Shares
    $spec.DeviceChange[0].Device.ResourceAllocation.Share.Level = $device.ResourceAllocation.Share.Level
    $spec.DeviceChange[0].Device.Connectable = New-Object VMware.Vim.VirtualDeviceConnectInfo
    $spec.DeviceChange[0].Device.Connectable.Connected = $true
    $spec.DeviceChange[0].Device.Connectable.MigrateConnect = 'unset'
    $spec.DeviceChange[0].Device.Connectable.AllowGuestControl = $true
    $spec.DeviceChange[0].Device.Connectable.StartConnected = $true
    $spec.DeviceChange[0].Device.Connectable.Status = 'ok'
    $spec.DeviceChange[0].Device.Backing = New-Object VMware.Vim.VirtualEthernetCardDistributedVirtualPortBackingInfo
    $spec.DeviceChange[0].Device.Backing.Port = New-Object VMware.Vim.DistributedVirtualSwitchPortConnection
    $spec.DeviceChange[0].Device.Backing.Port.SwitchUuid = $device.Backing.Port.SwitchUuid
    $spec.DeviceChange[0].Device.Backing.Port.PortgroupKey = $device.Backing.Port.PortgroupKey
    $spec.DeviceChange[0].Device.AddressType = $device.AddressType
    $spec.DeviceChange[0].Device.ControllerKey = $device.ControllerKey
    $spec.DeviceChange[0].Device.UnitNumber = $device.UnitNumber
    $spec.DeviceChange[0].Device.WakeOnLanEnabled = $true
    $spec.DeviceChange[0].Device.SlotInfo = New-Object VMware.Vim.VirtualDevicePciBusSlotInfo
    $spec.DeviceChange[0].Device.SlotInfo.PciSlotNumber = $device.SlotInfo.PciSlotNumber
    $spec.DeviceChange[0].Device.UptCompatibilityEnabled = $false
    $spec.DeviceChange[0].Device.DeviceInfo = New-Object VMware.Vim.Description
    $spec.DeviceChange[0].Device.DeviceInfo.Summary = $device.DeviceInfo.Summary
    $spec.DeviceChange[0].Device.DeviceInfo.Label = $device.DeviceInfo.Label
    $spec.DeviceChange[0].Device.Key = $device.Key
    $spec.DeviceChange[0].Operation = 'edit'
    $spec.CpuFeatureMask = New-Object VMware.Vim.VirtualMachineCpuIdInfoSpec[] (0)
    
    # Check if VMware Tools Update has failed
    If ($vm_spec.Config.Tools.LastInstalledInfo.Fault)
    {
        $spec.Tools = New-Object VMware.Vim.ToolsConfigInfo
        $spec.Tools.LastInstallInfo = New-Object VMware.Vim.ToolsConfigInfoToolsLastInstallInfo
        $spec.Tools.LastInstallInfo.Fault = New-Object VMware.Vim.VmToolsUpgradeFault
        $spec.Tools.LastInstallInfo.Fault.LocalizedMessage = $vm_spec.Config.Tools.LastInstallInfo.Fault.LocalizedMessage
        $spec.Tools.LastInstallInfo.Fault.Message = $vm_spec.Config.Tools.LastInstallInfo.Fault.Message
        $spec.Tools.LastInstallInfo.Counter = $vm_spec.Config.Tools.LastInstallInfo.Counter
    }

    ## Execute Task
    $_this = Get-View -Id $vm.Id
    $task = $_this.ReconfigVM_Task($spec)

    # Display task
    Write-Host $task -ForegroundColor "${WWLabelBackClr}"

    # While loop to check progress and exit on completion of migration
    While((Get-Task -Id $task).State -ne "Success")
    {
        #Do Nothing
    }

    # Display device is now connected
    Write-Host "Device is now connected!" -ForegroundColor "${successClr}"
    Write-Host " "
}

# Function to test a network adapter within the Guest OS is connected
Function adapterConnected($vm_spec, $port, $session)
{
    # Set $adapter_connected update variable to $false 
    $adapter_connected = $false
    
    # While loop to check update variable
    while($adapter_connected -ne $true)
    {      
        # Check Guest OS id
        If (($vm_spec.Guest.GuestId -eq "windows7Server64Guest") -OR ($vm_spec.Guest.GuestId -eq "windows7_64Guest"))
        {
            # Display compatibility method
            Write-Host "compatibility method" -ForegroundColor "${waitMsgClr}"

            # Get adapters on Guest OS
            $results = Invoke-Command -Session $session -ScriptBlock{(Get-WmiObject Win32_NetworkAdapter -Filter 'NetEnabled=True')}
            
            # For each adapter
            Foreach($adapter in $results)
            {
                # Check for adapter MacAddress match
                If ($adapter.MACAddress -eq $port.MacAddress)
                {
                    
                    # Display MacAddress
                    Write-Host $adapter.MACAddress -ForegroundColor "${waitMsgClr}"
                    
                    # Check for adapter speed (network link speed auto-negotiation occured)
                    If ($adapter.Speed)
                    {
                        # Display connection speed
                        Write-Host $adapter.Speed
                        
                        # Set update variable to $true
                        $adapter_connected = $true
                    }
                }
            }
        }
        Else
        {
            # Display default method
            Write-Host "default method" -ForegroundColor "${waitMsgClr}"

            # Get adapters on Guest OS            
            $results = Invoke-Command -Session $session -ScriptBlock{(Get-NetAdapter)}
            
            # For each adapter
            Foreach($adapter in $results)
            {
                # Check for adapter MacAddress match                
                If (($adapter.MacAddress -replace "-",":") -eq $port.MacAddress)
                {
                    # Display MacAddress                    
                    Write-Host ($adapter.MacAddress -replace "-",":") -ForegroundColor "${waitMsgClr}"
                    
                    # Check adapter status
                    If ($adapter.Status -eq "Up")
                    {
                        # Display connection status
                        Write-Host $adapter.Status
                        
                        # Set update variable to $true
                        $adapter_connected = $true
                    }
                }
            }                            
        }
    }
}

# Function to test network connection to vmkernal adapters (ensures network connectivity inbound/outbound)
Function netTest($machine, $port, $vm_spec, $session)
{
    # Update target network
    $target = $machine.IP.($port.NetworkName -Replace "[^a-zA-Z]","").ToLower()    

    # Display checking network connectivity
    Write-Host "Checking ${target} for connectivity..." -ForegroundColor "${actionClr}"

    # Get vmkernal IP Address for target network
    $vmkernal_ip = (Get-VMHostNetworkAdapter -PortGroup $port.NetworkName -VMHost (Get-Inventory | Where-Object {$_.Name -eq $machine.Host}).Name).IP
    Try
    {
        # Set session global variables            
        Invoke-Command -Session $session -ScriptBlock {$OriginalProgressPreference = $Global:ProgressPreference; $Global:ProgressPreference = $Using:warningPreference}
        
        # Test network connection of configured IP Address in Virtual Machine to ESXi Host vmkernal interface IP Address            
        $response = Invoke-Command -Session $session -ScriptBlock {Test-Connection $Using:vmkernal_ip -Count 1 -Quiet}
        #Start-Sleep -Seconds 1

        # Check response 
        If ($response -eq "True")
        {
            # Display success message
            Write-Host "Success!" -ForegroundColor "${successClr}"
            Write-Host " "
        }
        Else
        {
            # Display problem with network device
            Write-Host "Problem with network device. Check network interface $($port.NetworkName)." -ForegroundColor "${errClr}"
            Write-Host " "
        }
    }
    Catch
    {
        # Display network tesk failed
        Write-Host "The command could not complete as executed!" -ForegroundColor "${errClr}"
    }
}

# Function to connect to VMware vCenter
Function loginVCenter()
{
    # Display connecting to VMware vCenter
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
    Write-Host "Connecting to VMware vCenter at $($vCenter.IP)..." -ForegroundColor "${actionClr}"
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"   
    Connect-VIServer -Server $vCenter.IP -Protocol https -User $vCenter.username -Password $vCenter.password -ea SilentlyContinue | Out-Null
    
    # Check return object of Connect-VIServer
    If ($? -eq "True")
    {
        # Display VMware vCenter login status successful
        Write-Host "Successfully logged in!" -ForegroundColor "${successClr}"
        Write-Host " "
    }
    Else
    {
        # Display VMware vCenter login status failed
        Write-Host "Failed to login!" -ForegroundColor "${errClr}"
        Write-Host " "
        exit
    }
}

# Function to logout of VMware vCenter
Function logoutVCenter()
{
    # Display disconnecting from VMware vCenter
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
    Write-Host "Disconnecting from VMware vCenter..." -ForegroundColor "${actionClr}"
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
    Write-Host " "

    # Disconnect from VMware vCenter
    Disconnect-VIServer -Server $vCenter.IP -Force -Confirm:$false | Out-Null    
}

# Function to find ESXi Host VMware vCenter VM resides and check to ensure operational
Function findAndCheckVCenter()
{
    # Display checking for VMware vCenter
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
    Write-Host "Checking for a instance of VMware vCenter..." -ForegroundColor "${actionClr}"
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
    Write-Host ""

    # For each ESXi Host
    Foreach ($esxi_host in $esxis)
    {
        # Connect to target ESXi Host with $esxi_cred
        Connect-VIServer $esxi_host.IP -User $esxi_cred.username -Password $esxi_cred.password | Out-Null
        
        # Return VM Object
        $result = VMware.VimAutomation.Core\Get-VM -Name "VMware vCenter Server Appliance" -ErrorAction SilentlyContinue
        
        # If VM Object exists
        If($result)
        {
            # Sleep 15 seconds to ensure ESXi Host is not in Maintenance Mode
            Start-Sleep -Seconds 15

            # Display VMware vCenter VM is found 
            Write-Host "VMware vCenter Server Appliance VM found on $($esxi_host.Name)." -ForegroundColor "${waitMsgClr}"

            $result = VMware.VimAutomation.Core\Get-VM -Name "VMware vCenter Server Appliance" -ErrorAction SilentlyContinue

            # If VM is Powered On
            If($result.PowerState -eq "PoweredOn")
            {
                # Check web service is operational
                Start-ThreadJob -ScriptBlock $job_status -Name "Check_vCenter" -ArgumentList $vCenter.IP
            }
            Else 
            {
                # Start VM
                VMware.VimAutomation.Core\Start-VM -VM "VMware vCenter Server Appliance" -Confirm:$false | Out-Null 
                # Check web service is operational
                Start-ThreadJob -ScriptBlock $job_status -Name "Check_vCenter" -ArgumentList $vCenter.IP
            }
            
            # Wait until Jobs are finshed execution
            Get-Job | Wait-Job
            Remove-Job -State Completed -Confirm:$false

            # Display VMware vCenter operations are available 
            Write-Host ""
            Write-Host "VMware vCenter is operational!" -ForegroundColor "${successClr}"
            Write-Host ""
        }
    }
}

# Function to Power On target ESXi Host using Wake-On-Lan Functionality (Requires Configuration in Bios of ESXi Host and identification of MacAddress for PCI-e Adapter)
Function wakeUpEsxi($esxi_host)
{
    # Test Ip of ESXi Host is responding to network communications
    If ((Test-Connection $esxi_host.IP -Count 1 -Quiet) -eq $false)
    {
        # Check formatting of MacAddress for PCI-e card
        If ($esxi_host.PCIe.MacAddress1 -NotMatch "^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$") {
            Write-Warning "MacAddress: '$($esxi_host.MacAddres1)' is invalid; must be 6 hex bytes separated by :" 
            Continue      
        }

        # Create UDP client instance
        $UdpClient = New-Object System.Net.Sockets.UdpClient

        #$esxi_host.PCIe.MacAddress1
        # Format MacAddress and convert to Bytes
        $MAC = $esxi_host.PCIe.MacAddress1.Split(':') | ForEach-Object { [Byte]"0x$_" }

        # Construct the Packet
        $Packet = [Byte[]](,0xFF * 6) + ($MAC * 16)
        
        # Connect UDPClient to Broadcast Address for 192.168.1.0/24
        $UdpClient.Connect("192.168.1.255", 4000)
        # Send Packet
        $UdpClient.Send($Packet, $Packet.Length) | Out-Null
        # Clost UDPClient
        $UdpClient.Close()
        # Display to console that the Wake-On-Lan Packet was sent to the target ESXi Host
        Write-Host "Wake-on-Lan packet sent to $($esxi_host.Name)" -ForegroundColor "${waitMsgClr}"
    }
    Else 
    {
        # Display to console that the ESXi Host is already running and a Wake-On-Lan Packet does not need to be sent  
        Write-Host "$($esxi_host.Name) is already powered on! Nothing to do." -ForegroundColor "${successClr}"
    }
}

# Function to exit ESXi Host from Maintenance Mode
Function esxiMaintenanceStatus($esxi_host)
{
    # Connect to target ESXi Host
    Connect-VIServer $esxi_host.IP -User $esxi_cred.username -Password $esxi_cred.password | Out-Null
   
    # Get ESXi Host details 
    $esxi = VMware.VimAutomation.Core\Get-VMHost
    
    # Check if ESXi Host in Maintenance Mode
    If ($esxi.ConnectionState -eq "Maintenance")
    {
        $timeout = 0
        $target= Get-Inventory -Name $esxi_host.IP
        $_this = Get-View -Id $target.Id

        # Exit Maintenance Mode
        $_this.ExitMaintenanceMode_Task($timeout)

        #VMware.VimAutomation.Core\Set-VMHost -State Connected | Out-Null
        
        # Wait until ESXi Host has exited Maintenance Mode
        while((VMware.VimAutomation.Core\Get-VMHost).ConnectionState -ne "Connected")
        {
            # Do Nothing
        }
        
        # Display to console ESXi Host has left Maintenance Mode
        Write-Host "$($esxi_host.Name) has left maintenance mode!" -ForegroundColor "${successClr}"
        # Write-Host ""
        # Wait to check HA Agent Service
        Start-Sleep -Seconds 3
        
        # # Check to make sure HA Agent Service has started after Exiting Maintenace Mode and if not, Start the Service
        # If((VMware.VimAutomation.Core\Get-VMHostService | Where-Object {$_.key -eq "vmware-fdm"}).Running -eq "False")
        # {
        #     #Start HA Agent Service on ESXi Host
        #     VMware.VimAutomation.Core\Set-VMHostService -Service "vmware-fdm" -Confirm:$false
            
        # }
    }
    # ESXi Host not in Maintenance Mode
    ElseIf ($esxi.ConnectionState -eq "Connected") 
    {
        # Display to console that ESXi Host is not in Maintenance Mode
        Write-Host "$($esxi_host.Name) not in maintenance mode!" -ForegroundColor "${successClr}"

    }
    Else 
    {
      # Do Nothing   
    }

    # Disconnect from ESXi Host
    Disconnect-VIServer $esxi_host.IP -Confirm:$False | Out-Null
}

# Function to test ESXi Hosts are operational
Function esxiStartupCheck()
{
    # Display entering ESXi check operations
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}" 
    Write-Host "Ensuring all ESXi Hosts are powered on and operational..." -ForegroundColor "${actionClr}"
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor "${menuItemClr}"
    Write-Host ""

    # Power On ESXi Hosts and wait until ready
    Foreach ($esxi in $esxis)
    {
        # Wake-On-Lan function call for target ESXi Host
        wakeUpEsxi($esxi)
        # Execute ThreadJob to check web service operational for Powered On ESXi Host  
        Start-ThreadJob -ScriptBlock $job_status -Name "$($esxi.Name)_Check" -ArgumentList $esxi.IP | Out-Null
    }

    # Wait until all job threads have finished (ESXi Hosts have finished booting)
    Get-Job | Wait-Job 
    Remove-Job -State Completed -Confirm:$false

    # # Display all job have finished
    Write-Host ""
    Write-Host "All Jobs have finished" -ForegroundColor $successClr

    # For each ESXi Host, remove from Maintenance Mode
    Foreach ($esxi in $esxis)
    {
        esxiMaintenanceStatus($esxi)
    }
}

##========================================##
##     Main Loop of Powershell Script     ##
##========================================##
Function mainloop()
{
    [System.Console]::Clear()

    # ESXi Startup check and exit Maintenance Mode
    Write-Host "================================================================================" -ForegroundColor "${waitMsgClr}"
    Write-Host " "
    esxiStartupCheck

    # Locate and start VMware vCenter if not already started
    Write-Host "================================================================================" -ForegroundColor "${waitMsgClr}"
    Write-Host " "
    findAndCheckVCenter

    # Log into VMware vCenter
    Write-Host "================================================================================" -ForegroundColor "${waitMsgClr}"
    Write-Host " "
    loginVCenter

    # Sleep 2 seconds
    #Start-Sleep -Seconds 2

    # Display divider line to console
    Write-Host "================================================================================" -ForegroundColor "${waitMsgClr}"
    Write-Host " "
    
    Foreach ($machine in $machines)
    {
          hostCorrection($machine)
          StartVM($machine)
          checkToolsAndOS($machine)
          checkNetworking($machine)
          checkPrograms($machine)          
          Write-Host "================================================================================" -ForegroundColor "${waitMsgClr}"
          Write-Host " "
    }
    # Disconnect from all background PSSessions
    #Get-PSSession | Disconnect-PSSession | Out-Null

    # Logout of VMware vCenter
    logoutVCenter
}

##========================================##
## End of Main Loop of Powershell Script  ##
##========================================##


# mainloop function call
mainloop

# Prompt user to enter any key to exit
Write-Host -NoNewline "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

