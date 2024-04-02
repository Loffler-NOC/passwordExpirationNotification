<#
.SYNOPSIS
This PowerShell script sends password expiration notifications to users via email. It checks Active Directory for users whose
passwords are about to expire, calculates the days remaining until expiration, and sends an email with instructions on how to reset their passwords.
#>

# Set Execution Policy to Bypass for the current process
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Import required modules
Import-Module -Name ActiveDirectory
Import-Module -Name Microsoft.Graph.Users.Actions

############################
# DEFINE AND SET VARIABLES #
############################

# Password expiration threshold to start sending emails
$ExpireInDays = '7'

$ScriptLogging = 'Enabled' # Set to Disabled to disable logging
$ScriptDir = "$Env:SystemDrive\ScheduledTaskScripts\PasswordExpirationNotification"
$ScriptLog = "$ScriptDir\LOG-PasswordExpirationNotification.csv"

# If $TestMode is set to $Enabled, email $TestRecipient rather than the account that has their password expiring
$TestMode = 'Disabled'
$TestRecipient = 'username@domain.com'

# Azure App Registration connection variables
$CertThumbprint = 'REDACTED'
$Tenant = 'REDACTED'
$AzureAppID = 'REDACTED'

# Email address to send password expiration notifications from
$MailFrom = 'noreply@domain.com'

##########
# SCRIPT #
##########

# Get the local machine certificate and connect to Microsoft Graph
$LocalMachineCert = Get-ChildItem -Path "Cert:\LocalMachine\My\$CertThumbprint"
Connect-MgGraph -TenantId $Tenant -ClientId $AzureAppID -Certificate $LocalMachineCert

# Check if script logging is enabled and create log file if necessary
if ($ScriptLogging -eq 'Enabled') {
	if (!(Test-Path -Path "$ScriptDir")) {
		New-Item -Path "$ScriptDir" -ItemType 'Directory'

		New-Item -Path "$ScriptLog" -ItemType 'File'
		Add-Content -Path "$ScriptLog" -Value 'Date,Name,EmailAddress,DaysToExpire,ExpiresOn'
	}
}

# Get users from Active Directory whose passwords are about to expire
$Users = Get-ADUser -Filter '*' -Properties Name, PasswordNeverExpires, PasswordExpired, PasswordLastSet, EmailAddress |
	Where-Object { $_.Enabled -eq 'True' } |
	Where-Object { $_.PasswordNeverExpires -eq $false } |
	Where-Object { $_.PasswordExpired -eq $false }

# Get the default maximum password age policy from Active Directory
$DefaultMaxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge

# Iterate through each user
foreach ($User in $Users) {
	$Name = $User.Name
	$EmailAddress = $User.EmailAddress
	$PasswordSetDate = $User.PasswordLastSet

	# Get the password policy for the user
	$PasswordPol = (Get-ADUserResultantPasswordPolicy -Identity "$User")
	if ($null -ne $PasswordPol) {
		$MaxPasswordAge = ($PasswordPol).MaxPasswordAge
	}
	else {
		$MaxPasswordAge = $DefaultMaxPasswordAge
	}

	# Calculate password expiration date and days remaining
	$ExpiresOn = $PasswordSetDate + $MaxPasswordAge
	$Today = Get-Date
	$DaysToExpire = (New-TimeSpan -Start $Today -End $ExpiresOn).Days

	# Determine message content based on days to expire
	$MessageDays = $DaysToExpire
	if ($MessageDays -ge '1') {
		$MessageDays = 'in ' + "$DaysToExpire" + ' day(s)'
	}
	else {
		$MessageDays = 'today'
	}

	# Construct email subject and body
	$EmailSubject = "[Action Required] Your password will expire $MessageDays"
	$EmailBody = @"

	<!DOCTYPE html PUBLIC '-//W3C//DTD HTML 4.01 Transitional//EN' 'http://www.w3.org/TR/html4/loose.dtd'>
	<html lang='en'>
	
	<head>
		<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>
		<meta name='viewport' content='width=device-width, initial-scale=1'>
		<meta http-equiv='X-UA-Compatible' content='IE=edge'>
		<meta name='format-detection' content='telephone=no'>
		<style type='text/css'>
			body {
				margin: 0;
				padding: 0;
				-ms-text-size-adjust: 100%;
				-webkit-text-size-adjust: 100%;
			}
	
			table {
				border-spacing: 0;
			}
	
			table td {
				border-collapse: collapse;
			}
	
			.ExternalClass {
				width: 100%;
			}
	
			.ExternalClass,
			.ExternalClass p,
			.ExternalClass span,
			.ExternalClass font,
			.ExternalClass td,
			.ExternalClass div {
				line-height: 100%;
			}
	
			.ReadMsgBody {
				width: 100%;
				background-color: #ebebeb;
			}
	
			table {
				mso-table-lspace: 0pt;
			}
	
			img {
				-ms-interpolation-mode: bicubic;
			}
	
			.yshortcuts a {
				border-bottom: none !important;
			}
	
			@media screen and (max-width:599px) {
	
				table[class='force-row'],
				table[class='container'] {
					width: 100% !important;
					max-width: 100% !important;
				}
			}
	
			@media screen and (max-width:400px) {
				td[class*='container-padding'] {
					padding-left: 12px !important;
					padding-right: 12px !important;
				}
			}
	
			.ios-footer a {
				color: black !important;
				text-decoration: underline;
			}
		</style>
	</head>
	
	<body style='margin:0; padding:0;' bgcolor='#F0F0F0' leftmargin='0' topmargin='0' marginwidth='0' marginheight='0'>
	
		<table border='0' width='100%' height='100%' cellpadding='0' cellspacing='0' bgcolor='#F0F0F0'>
			<tr>
				<td align='center' valign='top' bgcolor='#F0F0F0' style='background-color: #F0F0F0;'><br>
					<table border='0' width='600' cellpadding='0' cellspacing='0' class='container'
						style='width:600px;max-width:600px'>
	
						<!-- MESSAGE HEADER -->
						<tr>
							<td class='container-padding header' align='left'
								style='font-family:Helvetica,Arial,sans-serif;font-size:24px;font-weight:bold;padding-bottom:12px;color:black;padding-left:24px;padding-right:24px'>
	
	Account Password Expiration
	
							</td>
						</tr>
	
						<!-- MESSAGE BODY -->
						<tr>
							<td class='container-padding content' align='left'
								style='padding-left:24px;padding-right:24px;padding-top:12px;padding-bottom:12px;background-color:#ffffff'>
								<br>
								<div class='title'
									style='font-family:Helvetica,Arial,sans-serif;font-size:18px;font-weight:600;color:#374550'>
	
	Dear $name,
	
								</div>
								<br>
								<div class='body-text'
									style='font-family:Helvetica,Arial,sans-serif;font-size:14px;line-height:20px;text-align:left;color:#333333'><strong>
	
	your password will expire $messageDays. Please review these steps to reset your password:
	
									</strong><br><br>
	
	Login to <b><a href='https://outlook.office365.com'>Outlook Online</a></b>. Click on your name (upper-right corner) and go to <i>View account > Change Password</i>
	
									<br><br>
	
	<b><a href='https://passwordreset.microsoftonline.com/'>Forgotten your password and need it reset? Use this link</a></b>. Enter your email address and follow the website steps to reset your password
	
									<br><br>
								</div>
							</td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
	
		<table border='0' width='100%' height='100%' cellpadding='0' cellspacing='0' bgcolor='#F0F0F0'>
			<tr>
				<td align='center' valign='top' bgcolor='#F0F0F0' style='background-color:#F0F0F0;'><br>
					<table border='0' width='600' cellpadding='0' cellspacing='0' class='container'
						style='width:600px;max-width:600px'>
	
						<!-- MESSAGE CELL PHONE NOTE -->
						<tr>
							<td class='container-padding content' align='left'
								style='padding-left:24px;padding-right:24px;padding-top:12px;padding-bottom:12px;background-color:#ffffff'>
								<br>
								<div class='body-text'
									style='font-family:Helvetica,Arial,sans-serif;font-size:14px;line-height:20px;text-align:left;color:#333333'>
	
	<strong><font color=green><i>Note:</i> If you access your account with a mobile device, be sure to update it with your newly set credentials once prompted</font>
	
								</div>
							</td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
	
		<table border='0' width='100%' height='100%' cellpadding='0' cellspacing='0' bgcolor='#F0F0F0'>
			<tr>
				<td align='center' valign='top' bgcolor='#F0F0F0' style='background-color:#F0F0F0;'><br>
					<table border='0' width='600' cellpadding='0' cellspacing='0' class='container'
						style='width:600px;max-width:600px'>
	
						<!-- MESSAGE REQUIREMENTS -->
						<tr>
							<td class='container-padding content' align='left'
								style='padding-left:24px;padding-right:24px;padding-top:12px;padding-bottom:12px;background-color:#ffffff'>
								<br>
								<div class='title'
	
	style='font-family:Helvetica,Arial,sans-serif;font-size:18px;font-weight:600;color:#374550'>Minimum Requirements:</div><br>
	
							</td>
						</tr>
	
						<!-- MESSAGE FOOTER -->
						<tr>
							<td class='container-padding footer-text' align='left'
								style='font-family:Helvetica,Arial,sans-serif;font-size:12px;line-height:16px;color:#aaaaaa;padding-left:24px;padding-right:24px'>
								<br><br>
								<strong>
	
	<font color='black'>Still have questions?
	
										<br>
	
	<a href='mailto:itdepartment@domain.com?subject=[Help Needed] Password Expiration'>Click here to email itdepartment@domain.com</a>
										<br><br>
	
	Office: (123) 456-7890
	
										<br><br>
	
	Company name
	
										<br>
										<span class='ios-footer'>
	
	Company address
	
											<br>
	
	City, State Zip
	
											<br>
										</span>
									</font>
								</strong>
								<br><br>
							</td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
	
	</body>
	
	</html>

"@

	# If $TestMode is Enabled or if the current user's email address attribute is empty, adjust the recipient email address to $TestRecipient
	if (($TestMode -eq 'Enabled') -or ($null -eq $EmailAddress)) {
		$EmailAddress = $TestRecipient
	}

	# Send notification email if password expiration is within specified threshold
	if (($DaysToExpire -ge '0') -and ($DaysToExpire -lt $ExpireInDays)) {
		if ($ScriptLogging -eq 'Enabled') {
			$Date = Get-Date -Format 'ddMMyyyy'
			Add-Content -Path "$ScriptLog" -Value "$Date,$Name,$EmailAddress,$DaysToExpire,$ExpiresOn"
		}

		# Construct the email message
		$Message = @{
			Subject = $EmailSubject
			Body = @{
				ContentType = "HTML"
				Content = $EmailBody
			}
			ToRecipients = @(
				@{
					EmailAddress = @{
						Address = $EmailAddress
					}
				}
			)
		}

		# Send the email message
		Send-MgUserMail -UserId $MailFrom -Message $Message
	}
}
