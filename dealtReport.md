## Map Controls
{
  "SV-218785": "SV-214400",
  "SV-218786": "SV-214401",
  "SV-218787": "SV-214402",
  "SV-218788": "SV-214403",
  "SV-218789": "SV-214404",
  "SV-218790": "SV-214405",
  "SV-218791": "SV-214406",
  "SV-218792": "SV-214407",
  "SV-218793": "SV-214408",
  "SV-218794": "SV-214409",
  "SV-218795": "SV-214410",
  "SV-218796": "SV-214411",
  "SV-218797": "SV-214412",
  "SV-218798": "SV-214413",
  "SV-218799": "SV-214414",
  "SV-218800": "SV-214415",
  "SV-218801": "SV-214416",
  "SV-218802": "SV-214417",
  "SV-218803": "SV-214418",
  "SV-218804": "SV-214419",
  "SV-218806": "SV-214421",
  "SV-218807": "SV-214422",
  "SV-218808": "SV-214423",
  "SV-218809": "SV-214424",
  "SV-218810": "SV-214425",
  "SV-218812": "SV-256987",
  "SV-218813": "SV-214428",
  "SV-218814": "SV-214429",
  "SV-218815": "SV-214430",
  "SV-218816": "SV-214431",
  "SV-218817": "SV-214432",
  "SV-218818": "SV-214433",
  "SV-218819": "SV-214434",
  "SV-218820": "SV-214435",
  "SV-218823": "SV-214438",
  "SV-218824": "SV-214440",
  "SV-218825": "SV-214441",
  "SV-218826": "SV-214442",
  "SV-228572": "SV-228573"
}
Total Mapped Controls: 39

Total Controls Available for Delta: 43
     Total Controls Found on XCCDF: 45
                    Match Controls: 39
        Possible Mismatch Controls: 0
          Duplicate Match Controls: 0
                 No Match Controls: 5
                New XCDDF Controls: 1

Statistics Validation ------------------------------------------
Match + Mismatch = Total Mapped Controls: (39+0=39) true
  Total Processed = Total XCCDF Controls: (39+0+0+5+1=45) true

## Automatic Update:  -> 

### New Controls:
+   SV-218805 - The IIS 10.0 web server must accept only system-generated session identifiers.
+   SV-218821 - An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved Transport Layer Security (TLS) version.
+   SV-218822 - The IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved Transport Layer Security (TLS) version.
+   SV-218827 - The IIS 10.0 web server must enable HTTP Strict Transport Security (HSTS).
+   SV-241788 - HTTPAPI Server version must be removed from the HTTP Response Header information.
+   SV-241789 - ASP.NET version must be removed from the HTTP Response Header information.


### Updated Check/Fixes:
#### Checks:
<details open>
  <summary>Click to expand.</summary>
SV-218785:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Click the "Logging" icon.

Under Format select "W3C".

Click "Select Fields", verify at a minimum the following fields are checked: Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer.

If not, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Click the "Logging" icon.

Under Format select "W3C".

Click "Select Fields", verify at a minimum the following fields are checked: Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer.

If not, this is a finding.

```
---
SV-218786:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 server name.

Click the "Logging" icon.

Under Log Event Destination, verify the "Both log file and ETW event" radio button is selected.

If the "Both log file and ETW event" radio button is not selected, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 server name.

Click the "Logging" icon.

Under Log Event Destination, verify the "Both log file and ETW event" radio button is selected.

If the "Both log file and ETW event" radio button is not selected, this is a finding.

```
---
SV-218787:
Old: 
```
Interview the System Administrator to review the configuration of the IIS 8.5 architecture and determine if inbound web traffic is passed through a proxy.

If the IIS 8.5 web server is receiving inbound web traffic through a proxy, the audit logs must be reviewed to determine if correct source information is being passed through by the proxy server.

Follow this procedure for web server and each website:

Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Click the "Logging" icon.

Click on "View log files" under the "Actions" pane.

When the log file is displayed, review source IP information in log entries and verify the entries do not reflect the IP address of the proxy server.

If the website is not behind a load balancer or proxy server, this is Not Applicable.

If the log entries in the log file(s) reflect the IP address of the proxy server as the source, this is a finding.

If provisions have been made to log the client IP via another field (i.e., utilizing X-Forwarded-For), this is not a finding.

```

Updated:
```
Interview the System Administrator to review the configuration of the IIS 10.0 architecture and determine if inbound web traffic is passed through a proxy.

If the IIS 10.0 web server is receiving inbound web traffic through a proxy, the audit logs must be reviewed to determine if correct source information is being passed through by the proxy server.

Follow this procedure for web server and each website:

Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Click the "Logging" icon.

Click on "View log files" under the "Actions" pane.

When the log file is displayed, review source IP information in log entries and verify the entries do not reflect the IP address of the proxy server.

If the website is not behind a load balancer or proxy server, this is Not Applicable.

If the log entries in the log file(s) reflect the IP address of the proxy server as the source, this is a finding.

If provisions have been made to log the client IP via another field (i.e., utilizing X-Forwarded-For), this is not a finding.

```
---
SV-218788:
Old: 
```
Access the IIS 8.5 web server IIS Manager.

Click the IIS 8.5 web server name.

Under "IIS", double-click the "Logging" icon.

Verify the "Format:" under "Log File" is configured to "W3C".

Select the "Fields" button.

Under "Custom Fields", verify the following fields have been configured:

Request Header >> Connection

Request Header >> Warning

If any of the above fields are not selected, this is a finding.

```

Updated:
```
Access the IIS 10.0 web server IIS Manager.
Click the IIS 10.0 web server name.
Under "IIS", double-click the "Logging" icon.
Verify the "Format:" under "Log File" is configured to "W3C".
Select the "Fields" button.
Under "Custom Fields", verify the following fields have been configured:
Request Header >> Connection
Request Header >> Warning
If any of the above fields are not selected, this is a finding.

```
---
SV-218789:
Old: 
```
Access the IIS 8.5 web server IIS Manager.
Click the IIS 8.5 web server name.
Under "IIS", double-click the "Logging" icon.
Verify the "Format:" under "Log File" is configured to "W3C".
Select the "Fields" button.
Under "Standard Fields", verify "User Agent", "User Name" and "Referrer" are selected.
Under "Custom Fields", verify the following field have been configured:
Request Header >> Authorization
Response Header >> Content-Type

If any of the above fields are not selected, this is a finding.

```

Updated:
```
Access the IIS 10.0 web server IIS Manager.
Click the IIS 10.0 web server name.
Under "IIS", double-click the "Logging" icon.
Verify the "Format:" under "Log File" is configured to "W3C".
Select the "Fields" button.
Under "Standard Fields", verify "User Agent", "User Name", and "Referrer" are selected.
Under "Custom Fields", verify the following field has been configured:
Request Header >> Authorization
Response Header >> Content-Type
If any of the above fields are not selected, this is a finding.

```
---
SV-218790:
Old: 
```
This check does not apply to service account IDs utilized by automated services necessary to process, manage, and store log files.

Open the IIS 8.5 Manager.
Click the IIS 8.5 web server name.
Click the "Logging" icon.
Click the "Browse" button and navigate to the directory where the log files are stored.
Right-click the log file name to review.
Click “Properties”.
Click the “Security” tab.

Verify log file access is restricted as follows. 

SYSTEM - Full Control
Administrators - Full Control

If log access is not restriced as listed above, this is a finding.

```

Updated:
```
This check does not apply to service account IDs utilized by automated services necessary to process, manage, and store log files.
Open the IIS 10.0 Manager.
Click the IIS 10.0 web server name.
Click the "Logging" icon.
Click "Browse" and navigate to the directory where the log files are stored.
Right-click the log file directory to review.
Click "Properties".
Click the "Security" tab.
Verify log file access is restricted as follows. Otherwise, this is a finding.
SYSTEM - Full Control
Administrators - Full Control

```
---
SV-218791:
Old: 
```
The IIS 8.5 web server and website log files should be backed up by the system backup.

To determine if log files are backed up by the system backup, determine the location of the web server log files and each website's log files.

Open the IIS 8.5 Manager.

Click the IIS 8.5 server name.

Click the "Logging" icon.

Under "Log File" >> "Directory" obtain the path of the log file.

Once all locations are known, consult with the System Administrator to review the server's backup procedure and policy.

Verify the paths of all log files are part of the system backup.
Verify log files are backed up to an unrelated system or onto separate media than the system the web server is running on.

If the paths of all log files are not part of the system backup and/or not backed up to a separate media, this is a finding.

```

Updated:
```
The IIS 10.0 web server and website log files should be backed up by the system backup.

To determine if log files are backed up by the system backup, determine the location of the web server log files and each website's log files.

Open the IIS 10.0 Manager.

Click the IIS 10.0 server name.

Click the "Logging" icon.

Under "Log File" >> "Directory" obtain the path of the log file.

Once all locations are known, consult with the System Administrator to review the server's backup procedure and policy.

Verify the paths of all log files are part of the system backup.
Verify log files are backed up to an unrelated system or onto separate media on which the system the web server is running.

If the paths of all log files are not part of the system backup and/or not backed up to a separate media, this is a finding.

```
---
SV-218792:
Old: 
```
Interview the System Administrator about the role of the IIS 8.5 web server.

If the IIS 8.5 web server is hosting an application, have the SA provide supporting documentation on how the application's user management is accomplished outside of the IIS 8.5 web server.

If the IIS 8.5 web server is not hosting an application, this is Not Applicable.

If the IIS web server is performing user management for hosted applications, this is a finding.

If the IIS 8.5 web server is hosting an application and the SA cannot provide supporting documentation on how the application's user management is accomplished outside of the IIS 8.5 web server, this is a finding.

```

Updated:
```
Interview the System Administrator about the role of the IIS 10.0 web server.

If the IIS 10.0 web server is hosting an application, have the SA provide supporting documentation on how the application's user management is accomplished outside of the IIS 10.0 web server.

If the IIS 10.0 web server is not hosting an application, this is Not Applicable.

If the IIS web server is performing user management for hosted applications, this is a finding.

If the IIS 10.0 web server is hosting an application and the SA cannot provide supporting documentation on how the application's user management is accomplished outside of the IIS 10.0 web server, this is a finding.

```
---
SV-218793:
Old: 
```
Click on “Start”.

Open Control Panel.

Click on “Programs”.

Click on “Programs and Features”.

Review the installed programs, if any programs are installed other than those required for the IIS 8.5 web services, this is a finding.

Note: If additional software is needed supporting documentation must be signed by the ISSO.

```

Updated:
```
Click “Start”.

Open Control Panel.

Click “Programs”.

Click “Programs and Features”.

Review the installed programs. If any programs are installed other than those required for the IIS 10.0 web services, this is a finding.

Note: If additional software is needed, supporting documentation must be signed by the ISSO.

```
---
SV-218794:
Old: 
```
Open the IIS 8.5 Manager.

Under the "Connections" pane on the left side of the management console, select the IIS 8.5 web server.

If, under the IIS installed features, "Application Request Routing Cache" is not present, this is not a finding.

If, under the IIS installed features, "Application Request Routing Cache" is present, double-click the icon to open the feature.

From the right "Actions" pane, under "Proxy", select "Server Proxy Settings...".

In the "Application Request Routing" settings window, verify whether "Enable proxy" is selected.

If “Enable proxy" is selected under the "Application Request Routing" settings, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Under the "Connections" pane on the left side of the management console, select the IIS 10.0 web server.

If, under the IIS installed features "Application Request Routing Cache" is not present, this is not a finding.

If, under the IIS installed features "Application Request Routing Cache" is present, double-click the icon to open the feature.

From the right "Actions" pane under "Proxy", select "Server Proxy Settings...".

In the "Application Request Routing" settings window, verify whether "Enable proxy" is selected.

If "Enable proxy" is selected under the "Application Request Routing" settings, this is a finding.

If the server has been approved to be a Proxy server, this requirement is Not Applicable.

```
---
SV-218796:
Old: 
```
Access the IIS 8.5 web server.

Access “Apps” menu. Under “Administrative Tools”, select “Computer Management”.

In left pane, expand "Local Users and Groups" and click on "Users".

Review the local users listed in the middle pane.

If any local accounts are present and were created by features which have been uninstalled or are not used, this is a finding.

```

Updated:
```
Access the IIS 10.0 web server.

Access “Apps” menu. Under “Administrative Tools”, select “Computer Management”.

In the left pane, expand "Local Users and Groups" and click "Users".

Review the local users listed in the middle pane.

If any local accounts are present and were created by features which have been uninstalled or are not used, this is a finding.

```
---
SV-218797:
Old: 
```
Consult with the System Administrator and review all of the IIS 8.5 and Operating System features installed.

Determine if any are installed which are no longer necessary for operation.

If any utility programs, features or modules are installed which are not necessary for operation, this is a finding.

If any unnecessary Operating System features are installed, this is a finding.

```

Updated:
```
Consult with the System Administrator and review all of the IIS 10.0 and Operating System features installed.

Determine if any features installed are no longer necessary for operation.

If any utility programs, features, or modules are installed which are not necessary for operation, this is a finding.

If any unnecessary Operating System features are installed, this is a finding.

```
---
SV-218798:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under IIS, double-click the “MIME Types” icon.

From the "Group by:" drop-down list, select "Content Type".

From the list of extensions under "Application", verify MIME types for OS shell program extensions have been removed, to include at a minimum, the following extensions:

.exe
.dll
.com
.bat
.csh

If any OS shell MIME types are configured, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under IIS, double-click the "MIME Types" icon.

From the "Group by:" drop-down list, select "Content Type".

From the list of extensions under "Application", verify MIME types for OS shell program extensions have been removed, to include at a minimum, the following extensions:

.exe
.dll
.com
.bat
.csh

If any OS shell MIME types are configured, this is a finding.

```
---
SV-218799:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Review the features listed under the “IIS" section.

If the "WebDAV Authoring Rules" icon exists, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Review the features listed under the “IIS" section.

If the "WebDAV Authoring Rules" icon exists, this is a finding.

```
---
SV-218800:
Old: 
```
Open the IIS 8.5 Manager.
Click the IIS 8.5 web server name.
Double-click the "Server Certificate" icon.
Double-click each certificate and verify the certificate path is to a DoD root CA.
If the “Issued By” field of the PKI certificate being used by the IIS 8.5 server/site does not indicate the issuing Certificate Authority (CA) is part of the DoD PKI or an approved ECA, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Server Certificate" icon.

Double-click each certificate and verify the certificate path is to a DoD root CA.

If the “Issued By” field of the PKI certificate being used by the IIS 10.0 server/site does not indicate the issuing Certificate Authority (CA) is part of the DoD PKI or an approved ECA, this is a finding.

```
---
SV-218802:
Old: 
```
Obtain a list of the user accounts with access to the system, including all local and domain accounts. 

Review the privileges to the web server for each account.

Verify with the system administrator or the ISSO that all privileged accounts are mission essential and documented.

Verify with the system administrator or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.

If undocumented privileged accounts are found, this is a finding.

If undocumented non-administrator access to shell scripts and operating system functions are found, this is a finding.

```

Updated:
```
Obtain a list of the user accounts with access to the system, including all local and domain accounts. 

Review the privileges to the web server for each account.

Verify with the system administrator or the ISSO that all privileged accounts are mission essential and documented.

Verify with the system administrator or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.

If undocumented privileged accounts are found, this is a finding.

If undocumented non-administrator access to shell scripts and operating system functions are found, this is a finding.

If this IIS 10 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

```
---
SV-218803:
Old: 
```
Review the IIS 8.5 web server configuration with the System Administrator.

Determine if the IIS 8.5 web server hosts any applications.

If the IIS 8.5 web server does not host any applications, this is Not Applicable.

If the IIS 8.5 web server hosts applications, review the application's management functionality and authentication methods with the System Administrator to determine if the management of the application is accomplished with the same functions and authentication methods as the web server management.

If the IIS 8.5 web server management and the application's management functionality is not separated, this is a finding.

```

Updated:
```
Review the IIS 10.0 web server configuration with the System Administrator.

Determine if the IIS 10.0 web server hosts any applications.

If the IIS 10.0 web server does not host any applications, this is Not Applicable.

If the IIS 10.0 web server is hosting Exchange, this is Not Applicable.

If the IIS 10.0 web server hosts applications, review the application's management functionality and authentication methods with the System Administrator to determine if the management of the application is accomplished with the same functions and authentication methods as the web server management.

If the IIS 10.0 web server management and the application's management functionality is not separated, this is a finding.

```
---
SV-218804:
Old: 
```
Note: If IIS 8.5 server/site is used only for system-to-system maintenance, does not allow users to connect to interface, and is restricted to specific system IPs, this is Not Applicable.

Open the IIS 8.5 Manager.
Click the IIS 8.5 web server name.
Under "ASP.Net", double-click on the "Session State" icon.
Under "Cookie Settings", verify the "Mode" has "Use Cookies" selected from the drop-down list.

If the "Cookie Settings" "Mode" is not set to "Use Cookies", this is a finding.

Alternative method:
Click the site name.
Select "Configuration Editor" under the "Management" section.
From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".
Verify the "cookieless" is set to "UseCookies".

If the "cookieless" is not set to "UseCookies", this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.
Click the IIS 10.0 web server name.
Under "ASP.Net", double-click the "Session State" icon.
Under "Cookie Settings", verify the "Mode" has "Use Cookies" selected from the drop-down list.
If the "Cookie Settings" "Mode" is not set to "Use Cookies", this is a finding.

Alternative method:

Click the site name.
Select "Configuration Editor" under the "Management" section.
From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".
Verify the "cookieless" is set to "UseCookies".
If the "cookieless" is not set to "UseCookies", this is a finding.

Note: If IIS 10.0 server/site is used only for system-to-system maintenance, does not allow users to connect to interface, and is restricted to specific system IPs, this is Not Applicable.

```
---
SV-218806:
Old: 
```
Interview the System Administrator for the IIS 8.5 web server.

Ask for documentation on the disaster recovery methods tested and planned for the IIS 8.5 web server in the event of the necessity for rollback.

If documentation for a disaster recovery has not been established, this is a finding.

```

Updated:
```
Interview the System Administrator for the IIS 10.0 web server.

Ask for documentation on the disaster recovery methods tested and planned for the IIS 10.0 web server in the event of the necessity for rollback.

If documentation for a disaster recovery has not been established, this is a finding.

```
---
SV-218807:
Old: 
```
If .NET is not installed, this is Not Applicable.

Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "Machine Key" icon in the website Home Pane.

Verify "HMACSHA256" or stronger encryption is selected for the Validation method and "Auto" is selected for the Encryption method.

If "HMACSHA256" or stronger encryption is not selected for the Validation method and/or "Auto" is not selected for the Encryption method, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Machine Key" icon in the website Home Pane.

Verify "HMACSHA256" or stronger encryption is selected for the Validation method and "Auto" is selected for the Encryption method.

If "HMACSHA256" or stronger encryption is not selected for the Validation method and/or "Auto" is not selected for the Encryption method, this is a finding.

If .NET is not installed, this is Not Applicable.

```
---
SV-218808:
Old: 
```
If the Directory Browsing IIS Feature is disabled, this is Not Applicable.

Open the IIS 8.5 Manager.
Click the IIS 8.5 web server name.
Double-click the "Directory Browsing" icon.
Under the “Actions” pane verify "Directory Browsing" is disabled.

If “Directory Browsing” is not disabled, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Directory Browsing" icon.

Under the “Actions” pane verify "Directory Browsing" is disabled.

If “Directory Browsing” is not disabled, this is a finding.

```
---
SV-218809:
Old: 
```
Access the IIS 8.5 Web Server.

Access an administrator command prompt and type "regedit <enter>" to access the server's registry.

Navigate to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ContentIndex\Catalogs\.

If this key exists, then indexing is enabled. 

If the key does not exist, this check is Not Applicable.

Review the Catalog keys to determine if directories other than web document directories are being indexed.

If so, this is a finding.

```

Updated:
```
Access the IIS 10.0 Web Server.

Access an administrator command prompt and type "regedit <enter>" to access the server's registry.

Navigate to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ContentIndex\Catalogs\.

If this key exists, then indexing is enabled. 

If the key does not exist, this check is Not Applicable.

Review the Catalog keys to determine if directories other than web document directories are being indexed.

If so, this is a finding.

```
---
SV-218810:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "Error Pages" icon.

Click on any error message and click "Edit Feature Setting" from the "Actions" Pane. This will apply to all error messages.

If the feature setting is not set to “Detailed errors for local requests and custom error pages for remote requests”, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Error Pages" icon.

Click any error message, and then click "Edit Feature Setting" from the "Actions" Pane. This will apply to all error messages.

If the feature setting is not set to "Detailed errors for local requests and custom error pages for remote requests", or "Custom error pages"  this is a finding.

```
---
SV-218812:
Old: 
```
Note:  This requirement applies to the Web Management Service. If the Web Management Service is not installed, this is Not Applicable.

Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under "Management", double-click "Management Service".

If "Enable remote connections" is not selected, this is Not Applicable.

If "Enable remote connections" is selected, review the entries under "IP Address Restrictions".

Verify only known, secure IP ranges are configured as "Allow".

If "IP Address Restrictions" are not configured or IP ranges configured to be "Allow" are not restrictive enough to prevent connections from nonsecure zones, this is a finding.

```

Updated:
```
Note: This requirement applies to the Web Management Service. If the Web Management Service is not installed, this is Not Applicable.

Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under "Management", double-click "Management Service".

If "Enable remote connections" is not selected, this is Not Applicable.

If "Enable remote connections" is selected, review the entries under "IP Address Restrictions".

Verify only known, secure IP ranges are configured as "Allow".

If "IP Address Restrictions" are not configured or IP ranges configured to "Allow" are not restrictive enough to prevent connections from nonsecure zones, this is a finding.

```
---
SV-218813:
Old: 
```
Interview the System Administrator and Web Manager.

Ask for documentation for the IIS 8.5 web server administration.

Verify there are documented procedures for shutting down an IIS 8.5 website in the event of an attack. The procedure should, at a minimum, provide the following steps:

Determine the respective website for the application at risk of an attack.

Access the IIS 8.5 web server IIS Manager.

Select the respective website.

In the "Actions" pane, under "Manage Website", click on "Stop".

If necessary, stop all websites.

If necessary, stop the IIS 8.5 web server by selecting the web server in the IIS Manager.

In the "Actions" pane, under "Manage Server", click on "Stop".

If the web server is not capable of or cannot be configured to disconnect or disable remote access to the hosted applications when necessary, this is a finding.

```

Updated:
```
Interview the System Administrator and Web Manager.

Ask for documentation for the IIS 10.0 web server administration.

Verify there are documented procedures for shutting down an IIS 10.0 website in the event of an attack. The procedure should, at a minimum, provide the following steps:

Determine the respective website for the application at risk of an attack.

Access the IIS 10.0 web server IIS Manager.

Select the respective website.

In the "Actions" pane, under "Manage Website", click "Stop".

If necessary, stop all websites.

If necessary, stop the IIS 10.0 web server by selecting the web server in the IIS Manager.

In the "Actions" pane, under "Manage Server", click "Stop".

If the web server is not capable or cannot be configured to disconnect or disable remote access to the hosted applications when necessary, this is a finding.

```
---
SV-218814:
Old: 
```
Open Explorer and navigate to the inetpub directory.
Right-click "inetpub" and select "Properties".
Click the "Security" tab.
Verify the permissions for the following users:

System: Full control
Administrators: Full control
TrustedInstaller: Full control
ALL APPLICATION PACKAGES (built-in security group): Read and execute
ALL RESTRICTED APPLICATION PACKAGES (built-in security group): Read and execute
Users: Read and execute, list folder contents
CREATOR OWNER: Full Control, Subfolders and files only

If the permissions are less restrictive than what is listed, this is a finding.

```

Updated:
```
Open Explorer and navigate to the inetpub directory.

Right-click "inetpub" and select "Properties".

Click the "Security" tab.

Verify the permissions for the following users; if the permissions are less restrictive, this is a finding.

System: Full control
Administrators: Full control
TrustedInstaller: Full control
ALL APPLICATION PACKAGES (built-in security group): Read and execute
ALL RESTRICTED APPLICATION PACKAGES (built-in security group): Read and execute
Users: Read and execute, list folder contents
CREATOR OWNER: Full Control, Subfolders and files only

```
---
SV-218815:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under "IIS" double-click on the "Logging" icon.

In the "Logging" configuration box, determine the "Directory:" to which the "W3C" logging is being written.

Confirm with the System Administrator that the designated log path is of sufficient size to maintain the logging.

Under "Log File Rollover", verify the "Do not create new log files" is not selected.

Verify a schedule is configured to rollover log files on a regular basis.

Consult with the System Administrator to determine if there is a documented process for moving the log files off of the IIS 8.5 web server to another logging device.

If the designated logging path device is not of sufficient space to maintain all log files and there is not a schedule to rollover files on a regular basis, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under "IIS" double-click the "Logging" icon.

In the "Logging" configuration box, determine the "Directory:" to which the "W3C" logging is being written.

Confirm with the System Administrator that the designated log path is of sufficient size to maintain the logging.

Under "Log File Rollover", verify "Do not create new log files" is not selected.

Verify a schedule is configured to rollover log files on a regular basis.

Consult with the System Administrator to determine if there is a documented process for moving the log files off of the IIS 10.0 web server to another logging device.

If the designated logging path device is not of sufficient space to maintain all log files, and there is not a schedule to rollover files on a regular basis, this is a finding.

```
---
SV-218816:
Old: 
```
Right-click InetMgr.exe, then click “Properties” from the “Context” menu.

Select the "Security" tab.

Review the groups and user names.

The following account may have Full control privileges:

TrustedInstaller
Web Managers
Web Manager designees

The following accounts may have read and execute, or read permissions:

Non Web Manager Administrators
ALL APPLICATION PACKAGES (built-in security group)
SYSTEM
Users

Specific users may be granted read and execute and read permissions.

Compare the local documentation authorizing specific users, against the users observed when reviewing the groups and users.

If any other access is observed, this is a finding.

```

Updated:
```
Right-click "InetMgr.exe", then click "Properties" from the "Context" menu.

Select the "Security" tab.

Review the groups and user names.

The following accounts may have Full control privileges:

TrustedInstaller
Web Managers
Web Manager designees
CREATOR OWNER: Full Control, Subfolders and files only

The following accounts may have read and execute, or read permissions:

Non Web Manager Administrators
ALL APPLICATION PACKAGES (built-in security group)
ALL RESTRICTED APPLICATION PACKAGES (built-in security group)
SYSTEM
Users

Specific users may be granted read and execute and read permissions.

Compare the local documentation authorizing specific users, against the users observed when reviewing the groups and users.

If any other access is observed, this is a finding.

```
---
SV-218818:
Old: 
```
If the Print Services role and the Internet Printing role are not installed, this check is Not Applicable.

Navigate to the following directory:

%windir%\web\printers

If this folder exists, this is a finding.

Determine whether Internet Printing is enabled:

Click “Start”, then click “Administrative Tools”, and then click “Server Manager”.

Expand the roles node, then right-click “Print Services”, and then select “Remove Roles Services”.

If the Internet Printing option is enabled, this is a finding.

```

Updated:
```
If the Print Services role and the Internet Printing role are not installed, this check is Not Applicable.

Navigate to the following directory:

%windir%\web\printers

If this folder exists, this is a finding.

Determine whether Internet Printing is enabled:

Click “Start”, click “Administrative Tools”, and then click “Server Manager”.

Expand the roles node, right-click “Print Services”, and then select “Remove Roles Services”.

If the Internet Printing option is enabled, this is a finding.

```
---
SV-218819:
Old: 
```
If the IIS 8.5 web server is not hosting any applications, this is Not Applicable.

If the IIS 8.5 web server is hosting applications, consult with the System Administrator to determine risk analysis performed when application was written and deployed to the IIS 8.5 web server.

Obtain documentation on the configuration.

Verify, at a minimum, the following tuning settings in the registry.

Access the IIS 8.5 web server registry.

Verify the following values are present and configured. The required setting depends upon the requirements of the application. 

Recommended settings are not provided as these settings have to be explicitly configured to show a conscientious tuning has been made.

Navigate to HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\
"URIEnableCache"
"UriMaxUriBytes"
"UriScavengerPeriod"

If explicit settings are not configured for "URIEnableCache", "UriMaxUriBytes" and "UriScavengerPeriod", this is a finding.

```

Updated:
```
If the IIS 10.0 web server is not hosting any applications, this is Not Applicable.

If the IIS 10.0 web server is hosting applications, consult with the System Administrator to determine risk analysis performed when the application was written and deployed to the IIS 10.0 web server.

Obtain documentation on the configuration.

Verify, at a minimum, the following tuning settings in the registry.

Access the IIS 10.0 web server registry.

Verify the following keys are present and configured. The required setting depends upon the requirements of the application. 

Recommended settings are not provided as these settings must be explicitly configured to show a conscientious tuning has been made.

Navigate to HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\
"URIEnableCache"
"UriMaxUriBytes"
"UriScavengerPeriod"

If explicit settings are not configured for "URIEnableCache", "UriMaxUriBytes" and "UriScavengerPeriod", this is a finding.

```
---
SV-218820:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under "Management" section, double-click the "Configuration Editor" icon.

From the "Section:" drop-down list, select “system.webServer/asp".

Expand the "session" section.

Verify the "keepSessionIdSecure" is set to "True".

If the "keepSessionIdSecure" is not set to "True", this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under the "Management" section, double-click the "Configuration Editor" icon.

From the "Section:" drop-down list, select "system.webServer/asp".

Expand the "session" section.

Verify the "keepSessionIdSecure" is set to "True".

If the "keepSessionIdSecure" is not set to "True", this is a finding.

```
---
SV-218823:
Old: 
```
Access the IIS 8.5 web server.

Access Apps menu. Under Administrative Tools, select Computer Management.

In left pane, expand "Local Users and Groups" and click on "Users".

Review the local users listed in the middle pane. 

If any local accounts are present and are used by IIS 8.5 verify with System Administrator that default passwords have been changed.

If passwords have not been changed from the default, this is a finding.

```

Updated:
```
Access the IIS 10.0 web server.

Access the "Apps" menu. Under "Administrative Tools", select "Computer Management".

In left pane, expand "Local Users and Groups" and click "Users".

Review the local users listed in the middle pane. 

If any local accounts are present and used by IIS 10.0, verify with System Administrator that default passwords have been changed.

If passwords have not been changed from the default, this is a finding.

```
---
SV-218824:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "ISAPI and CGI restrictions" icon.

Click “Edit Feature Settings".

Verify the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes are NOT checked.

If either or both of the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes are checked, this is a finding.

```

Updated:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "ISAPI and CGI restrictions" icon.

Click “Edit Feature Settings".

Verify the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes are NOT checked.

If either or both of the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes are checked, this is a finding.

```
---
SV-218825:
Old: 
```
If ASP.NET is not installed, this is Not Applicable.
If the server is hosting SharePoint, this is Not Applicable.
If the server is hosting WSUS, this is Not Applicable.
If the server is hosting Exchange, this is Not Applicable.

Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the ".NET Authorization Rules" icon.

Ensure "All Users" is set to "Allow", and "Anonymous Users" is set to "Deny", otherwise this is a finding.
If any other rules are present, this is a finding.

```

Updated:
```
Note: If ASP.NET is not installed, this is Not Applicable.
Note: If the Server is hosting Microsoft SharePoint, this is Not Applicable.
Note: If the server is hosting WSUS, this is Not Applicable.
Note: If the server is hosting Exchange, this is Not Applicable.
Note: If the server is public facing, this is Not Applicable.

Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the ".NET Authorization Rules" icon.

Ensure "All Users" is set to "Allow", and "Anonymous Users" is set to "Deny", otherwise this is a finding.
If any other rules are present, this is a finding.

```
---
SV-218826:
Old: 
```
Access the IIS 8.5 IIS Manager.

Click the IIS 8.5 server.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.applicationHost/sites".

Expand "siteDefaults".
Expand "limits".

Review the results and verify the value is greater than zero for the "maxconnections" parameter.

If the maxconnections parameter is set to zero, this is a finding.

```

Updated:
```
Access the IIS 10.0 IIS Manager.

Click the IIS 10.0 server.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.applicationHost/sites".

Expand "siteDefaults".
Expand "limits".

Review the results and verify the value is greater than zero for the "maxconnections" parameter.

If the maxconnections parameter is set to zero, this is a finding.

```
---
SV-228572:
Old: 
```
Interview the System Administrator about the role of the IIS 8.5 web server.

If the IIS 8.5 web server is running SMTP relay services, have the SA provide supporting documentation on how the server is hardened. A DoD-issued certificate, and specific allowed IP address should be configured.

If the IIS 8.5 web server is not running SMTP relay services, this is Not Applicable.

If the IIS web server running SMTP relay services without TLS enabled, this is a finding.

If the IIS web server running SMTP relay services is not configured to only allow a specific IP address, from the same network as the relay, this is a finding.

```

Updated:
```
Interview the System Administrator about the role of the IIS 10.0 web server.

If the IIS 10.0 web server is running SMTP relay services, have the SA provide supporting documentation on how the server is hardened. A DoD-issued certificate, and specific allowed IP address should be configured.

If the IIS web server is not running SMTP relay services, this is Not Applicable.

If the IIS web server running SMTP relay services without TLS enabled, this is a finding.

If the IIS web server running SMTP relay services is not configured to only allow a specific IP address, from the same network as the relay, this is a finding.

```
---
</details>

#### Fixes:
<details open>
  <summary>Click to expand.</summary>
SV-218785:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Click the "Logging" icon.

Under Format select "W3C".

Select the following fields: Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer.

Under the "Actions" pane, click "Apply".

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Click the "Logging" icon.

Under Format select "W3C".

Select the following fields: Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer.

Under the "Actions" pane, click "Apply".

```
---
SV-218786:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 server name.

Click the "Logging" icon.

Under Log Event Destination, select the "Both log file and ETW event" radio button.

Under the "Actions" pane, click "Apply".

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 server name.

Click the "Logging" icon.

Under Log Event Destination, select the "Both log file and ETW event" radio button.

Under the "Actions" pane, click "Apply".

```
---
SV-218787:
Old: 
```
Access the proxy server through which inbound web traffic is passed and configure settings to pass web traffic to the IIS 8.5 web server transparently.

```
New:
```
Access the proxy server through which inbound web traffic is passed and configure settings to pass web traffic to the IIS 10.0 web server transparently.

```
---
SV-218788:
Old: 
```
Access the IIS 8.5 web server IIS Manager.
Click the IIS 8.5 web server name.
Under "IIS", double-click the "Logging" icon.
Verify the "Format:" under "Log File" is configured to "W3C".
Select the "Fields" button.
Under "Custom Fields", click the "Add Field..." button.
For each field being added, give a name unique to what the field is capturing.
Click on the "Source Type" drop-down list and select "Request Header".
Click on the "Source" drop-down list and select "Connection".
Click “OK” to add.

Click on the "Source Type" drop-down list and select "Request Header".
Click on the "Source" drop-down list and select "Warning".
Click “OK” to add.
Click "Apply" under the "Actions" pane.

```
New:
```
Access the IIS 10.0 web server IIS Manager.
Click the IIS 10.0 web server name.
Under "IIS", double-click the "Logging" icon.
Verify the "Format:" under "Log File" is configured to "W3C".
Select the "Fields" button.
Under "Custom Fields", click the "Add Field..." button.
For each field being added, give a name unique to what the field is capturing.
Click on the "Source Type" drop-down list and select "Request Header".
Click on the "Source" drop-down list and select "Connection".
Click "OK" to add.

Click on the "Source Type" drop-down list and select "Request Header".
Click on the "Source" drop-down list and select "Warning".
Click "OK" to add.
Click "Apply" under the "Actions" pane.

```
---
SV-218789:
Old: 
```
Access the IIS 8.5 web server IIS Manager.
Click the IIS 8.5 web server name.
Under "IIS", double-click the "Logging" icon.
Verify the "Format:" under "Log File" is configured to "W3C".
Select the "Fields" button.
Under "Standard Fields", select "User Agent", "User Name", and "Referrer".
Under "Custom Fields", select the following fields:
Click on the "Source Type" drop-down list and select "Request Header".
Click on the "Source" drop-down list and select "Authorization".
Click "OK" to add.

Click on the "Source" drop-down list and select "Content-Type".
Click on the "Source Type" drop-down list and select "Response Header".
Click "OK" to add.
Click "OK".
Click "Apply" under the "Actions" pane.

```
New:
```
Access the IIS 10.0 web server IIS Manager.
Click the IIS 10.0 web server name.
Under "IIS", double-click the "Logging" icon.
Verify the "Format:" under "Log File" is configured to "W3C".
Select the "Fields" button.
Under "Standard Fields", select "User Agent", "User Name", and "Referrer".
Under "Custom Fields", select the following fields:
Click on the "Source Type" drop-down list and select "Request Header".
Click on the "Source" drop-down list and select "Authorization".
Click "OK" to add.

Click on the "Source" drop-down list and select "Content-Type".
Click on the "Source Type" drop-down list and select "Response Header".
Click "OK" to add.
Click "OK".
Click "Apply" under the "Actions" pane.

```
---
SV-218790:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Click the "Logging" icon.

Click the "Browse" button and navigate to the directory where the log files are stored.

Right-click the log file name to review and click “Properties”.

Click the "Security" tab.

Set the log file permissions for the appropriate group(s).

Click "OK".

Select "Apply" in the "Actions" pane.

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Click the "Logging" icon.

Click "Browse" and navigate to the directory where the log files are stored.

Right-click the log file directory to review and click "Properties".

Click the "Security" tab.

Set the log file permissions for the appropriate group(s).

Click "OK".

Select "Apply" in the "Actions" pane.

```
---
SV-218791:
Old: 
```
Configure system backups to include the directory paths of all IIS 8.5 web server and website log files.

```
New:
```
Configure system backups to include the directory paths of all IIS 10.0 web server and website log files.

```
---
SV-218792:
Old: 
```
Reconfigure any hosted applications on the IIS 8.5 web server to perform user management outside the IIS 8.5 web server.

Document how the hosted application user management is accomplished.

```
New:
```
Reconfigure any hosted applications on the IIS 10.0 web server to perform user management outside the IIS 10.0 web server.

Document how the hosted application user management is accomplished.

```
---
SV-218793:
Old: 
```
Remove all unapproved programs and roles from the production IIS 8.5 web server.

```
New:
```
Remove all unapproved programs and roles from the production IIS 10.0 web server.

```
---
SV-218794:
Old: 
```
Open the IIS 8.5 Manager.

Under the "Connections" pane on the left side of the management console, select the IIS 8.5 web server.

Under the IIS installed features, "Application Request Routing Cache" is present, double-click the icon to open the feature.

From the right "Actions" pane, under "Proxy", select "Server Proxy Settings...".

In the "Application Request Routing" settings window, remove the check from the "Enable proxy" check box.

Click "Apply" in the "Actions" pane.

```
New:
```
Open the IIS 10.0 Manager.

Under the "Connections" pane on the left side of the management console, select the IIS 10.0 web server.

Under the IIS installed features, if "Application Request Routing Cache" is present, double-click the icon to open the feature.

From the right "Actions" pane, under "Proxy", select "Server Proxy Settings...".

In the "Application Request Routing" settings window, remove the check from the "Enable proxy" check box.

Click "Apply" in the "Actions" pane.

```
---
SV-218796:
Old: 
```
Access the IIS 8.5 web server.

Access “Apps” menu. Under “Administrative Tools”, select “Computer Management”.

In left pane, expand "Local Users and Groups" and click on "Users".

Delete any local accounts which were created by features which have been uninstalled or are not used.

```
New:
```
Access the IIS 10.0 web server.

Access “Apps” menu. Under “Administrative Tools”, select “Computer Management”.

In the left pane, expand "Local Users and Groups" and click "Users".

Delete any local accounts which were created by features which have been uninstalled or are not used.

```
---
SV-218797:
Old: 
```
Remove all utility programs, Operating System features or modules which are installed but are not necessary for web server operation.

```
New:
```
Remove all utility programs, Operating System features, or modules installed that are not necessary for web server operation.

```
---
SV-218798:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under IIS, double-click the “MIME Types” icon.

From the "Group by:" drop-down list, select "Content Type".

From the list of extensions under "Application", remove MIME types for OS shell program extensions, to include at a minimum, the following extensions:

.exe
.dll
.com
.bat
.csh

Under the "Actions" pane, click "Apply".

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under IIS, double-click the "MIME Types" icon.

From the "Group by:" drop-down list, select "Content Type".

From the list of extensions under "Application", remove MIME types for OS shell program extensions, to include at a minimum, the following extensions:

.exe
.dll
.com
.bat
.csh

Under the "Actions" pane, click "Apply".

```
---
SV-218799:
Old: 
```
Access Server Manager on the IIS 8.5 web server.

Click the IIS 8.5 web server name.

Click on "Manage".

Select "Add Roles and Features".

Click "Next" on the "Before you begin" dialog box.

Select "Role-based or feature-based installation" on the "Installation Type" dialog box and click on "Next".

Select the IIS 8.5 web server on the "Server Selection" dialog box.

From the "Windows Features" dialog box, navigate to "World Wide Web Services" >> "Common HTTP Features".

De-select "WebDAV Publishing" and click "Next" to complete removing the WebDAV Publishing feature from the IIS 8.5 web server.

```
New:
```
Access Server Manager on the IIS 10.0 web server.

Click the IIS 10.0 web server name.

Click on "Manage".

Select "Add Roles and Features".

Click "Next" in the "Before you begin" dialog box.

Select "Role-based or feature-based installation" on the "Installation Type" dialog box and click "Next".

Select the IIS 10.0 web server in the "Server Selection" dialog box.

From the "Windows Features" dialog box, navigate to "World Wide Web Services" >> "Common HTTP Features".

De-select "WebDAV Publishing", and click "Next" to complete removing the WebDAV Publishing feature from the IIS 10.0 web server.

```
---
SV-218800:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "Server Certificate" icon.

Import a valid DoD certificate and remove any non-DoD certificates.

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Server Certificate" icon.

Import a valid DoD certificate and remove any non-DoD certificates.

```
---
SV-218803:
Old: 
```
Develop a method to manage the hosted applications, either by moving its management functions off of the IIS 8.5 web server or by accessing the application's management via a uniquely assigned IP address.

```
New:
```
Develop a method to manage the hosted applications, either by moving its management functions off of the IIS 10.0 web server or by accessing the application's management via a uniquely assigned IP address.

```
---
SV-218804:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under "ASP.Net", double-click on the "Session State" icon.

Under "Cookie Settings", select "Use Cookies” from the "Mode" drop-down list.

Click "Apply" in the "Actions" pane.

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under "ASP.Net", double-click the "Session State" icon.

Under "Cookie Settings", select "Use Cookies” from the "Mode" drop-down list.

Click "Apply" in the "Actions" pane.

```
---
SV-218806:
Old: 
```
Prepare documentation for disaster recovery methods for the IIS 8.5 web server in the event of the necessity for rollback.

Document and test the disaster recovery methods designed.

```
New:
```
Prepare documentation for disaster recovery methods for the IIS 10.0 web server in the event of the necessity for rollback.

Document and test the disaster recovery methods designed.

```
---
SV-218807:
Old: 
```
If .NET is not installed, this is Not Applicable.

Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "Machine Key" icon in the web server Home Pane.

Set the Validation method to "HMACSHA256" or stronger.
Set the Encryption method to "Auto".

Click "Apply" in the "Actions" pane.

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Machine Key" icon in the web server Home Pane.

Set the Validation method to "HMACSHA256" or stronger.
Set the Encryption method to "Auto".

Click "Apply" in the "Actions" pane.

```
---
SV-218808:
Old: 
```
If the Directory Browsing IIS Feature is disabled, this is Not Applicable.

Open the IIS 8.5 Manager.
Click the IIS 8.5 web server name.
Double-click the "Directory Browsing" icon.
Under the "Actions" pane click "Disabled".
Under the "Actions" pane, click "Apply".

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Directory Browsing" icon.

Under the "Actions" pane click "Disabled".

Under the "Actions" pane, click "Apply".

```
---
SV-218810:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "Error Pages" icon.

Click on any error message and click "Edit Feature Setting" from the "Actions" Pane. This will apply to all error messages.

Set Feature Setting to “Detailed errors for local requests and custom error pages for remote requests”.

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Error Pages" icon.

Click any error message, and then click "Edit Feature Setting" from the "Actions" Pane. This will apply to all error messages.

Set Feature Setting to "Detailed errors for local requests and custom error pages for remote requests" or "Custom error pages".

```
---
SV-218812:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under "Management", double-click "Management Service".

Stop the Web Management Service under the "Actions" pane.

Configure only known, secure IP ranges are configured as "Allow".

Select "Apply" in "Actions" pane.

Restart the Web Management Service under the "Actions" pane.

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under "Management", double-click "Management Service".

Stop the Web Management Service under the "Actions" pane.

Configure only known, secure IP ranges as "Allow".

Select "Apply" in "Actions" pane.

Restart the Web Management Service under the "Actions" pane.

```
---
SV-218813:
Old: 
```
Prepare documented procedures for shutting down an IIS 8.5 website in the event of an attack.

The procedure should, at a minimum, provide the following steps:

Determine the respective website for the application at risk of an attack.

Access the IIS 8.5 web server IIS Manager.

Select the respective website. 

In the "Actions" pane, under "Manage Website", click on "Stop".

If necessary, stop all websites.

If necessary, stop the IIS 8.5 web server by selecting the web server in the IIS Manager.

In the "Actions" pane, under "Manage Server", click on "Stop".

```
New:
```
Prepare documented procedures for shutting down an IIS 10.0 website in the event of an attack.

The procedure should, at a minimum, provide the following steps:

Determine the respective website for the application at risk of an attack.

Access the IIS 10.0 web server IIS Manager.

Select the respective website. 

In the "Actions" pane, under "Manage Website", click "Stop".

If necessary, stop all websites.

If necessary, stop the IIS 10.0 web server by selecting the web server in the IIS Manager.

In the "Actions" pane, under "Manage Server", click "Stop".

```
---
SV-218815:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under "IIS" double-click on the "Logging" icon.

If necessary, in the "Logging" configuration box, re-designate a log path to a location able to house the logs.

Under "Log File Rollover", de-select the "Do not create new log files" setting.

Configure a schedule to rollover log files on a regular basis.

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under "IIS" double-click on the "Logging" icon.

If necessary, in the "Logging" configuration box, re-designate a log path to a location able to house the logs.

Under "Log File Rollover", de-select the "Do not create new log files" setting.

Configure a schedule to rollover log files on a regular basis.

```
---
SV-218818:
Old: 
```
Click “Start”, then click “Administrative Tools”, and then click “Server Manager”.

Expand the roles node, then right-click “Print Services”, and then select “Remove Roles Services”.

If the Internet Printing option is checked, clear the check box, click “Next”, and then click “Remove” to complete the wizard.

```
New:
```
Click “Start”, click “Administrative Tools”, and then click “Server Manager”.

Expand the roles node, right-click “Print Services”, and then select “Remove Roles Services”.

If the Internet Printing option is checked, clear the check box, click “Next”, and then click “Remove” to complete the wizard.

```
---
SV-218819:
Old: 
```
Access the IIS 8.5 web server registry.

Verify the following values are present and configured. The required setting depends upon the requirements of the application. These settings have to be explicitly configured to show a conscientious tuning has been made.

Navigate to HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\

Configure the following registry keys to levels to accommodate the hosted applications.

"URIEnableCache"
"UriMaxUriBytes"
"UriScavengerPeriod"

```
New:
```
Access the IIS 10.0 web server registry.

Verify the following keys are present and configured. The required setting depends upon the requirements of the application. These settings must be explicitly configured to show a conscientious tuning has been made.

Navigate to HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\

Configure the following registry keys to levels to accommodate the hosted applications.

"URIEnableCache"
"UriMaxUriBytes"
"UriScavengerPeriod"

```
---
SV-218820:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under "Management" section, double-click the "Configuration Editor" icon.

From the "Section:" drop-down list, select 'system.webServer/asp".

Expand the "session" section.

Select "True" for the "keepSessionIdSecure" setting.

Select "Apply" from the "Actions" pane.

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under "Management" section, double-click the "Configuration Editor" icon.

From the "Section:" drop-down list, select "system.webServer/asp".

Expand the "session" section.

Select "True" for the "keepSessionIdSecure" setting.

Select "Apply" from the "Actions" pane.

```
---
SV-218823:
Old: 
```
Access the IIS 8.5 web server.

Access Apps menu. Under Administrative Tools, select Computer Management.

In left pane, expand "Local Users and Groups" and click on "Users".

Change passwords for any local accounts are present and are used by IIS 8.5 verify with System Administrator that default passwords have been changed.

Develop an internal process for changing passwords on a regular basis.

```
New:
```
Access the IIS 10.0 web server.

Access the "Apps" menu. Under Administrative Tools, select Computer Management.

In left pane, expand "Local Users and Groups" and click on "Users".

Change passwords for any local accounts present that are used by IIS 10.0, then verify with System Administrator default passwords have been changed.

Develop an internal process for changing passwords on a regular basis.

```
---
SV-218824:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "ISAPI and CGI restrictions" icon.

Click "Edit Feature Settings".

Remove the check from the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes.

Click OK.

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "ISAPI and CGI restrictions" icon.

Click "Edit Feature Settings".

Remove the check from the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes.

Click "OK".

```
---
SV-218825:
Old: 
```
Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the ".NET Authorization Rules" icon.

Alter the list as necessary to ensure "All Users" is set to "Allow" and "Anonymous Users" is set to "Deny".

Remove any other line items.

```
New:
```
Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the ".NET Authorization Rules" icon.

Alter the list as necessary to ensure "All Users" is set to "Allow" and "Anonymous Users" is set to "Deny".

Remove any other line items.

```
---
SV-218826:
Old: 
```
Access the IIS 8.5 IIS Manager.

Click the IIS 8.5 server.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.applicationHost/sites".

Expand "siteDefaults".
Expand "limits".

Set the "maxconnections" parameter to a value greater than zero.

```
New:
```
Access the IIS 10.0 IIS Manager.

Click the IIS 10.0 server.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.applicationHost/sites".

Expand "siteDefaults".
Expand "limits".

Set the "maxconnections" parameter to a value greater than zero.

```
---
</details>

### Updated Impacts
<details open>
  <summary>Click to expand.</summary>
SV-218809:
Old: 0
New: 0.5
---
</details>

### Updated Titles
<details>
  <summary>Click to expand.</summary>
SV-218785:
Old: The enhanced logging for the IIS 8.5 web server must be enabled and capture all user and web server events.
New: The enhanced logging for the IIS 10.0 web server must be enabled and capture all user and web server events.
---
SV-218786:
Old: Both the log file and Event Tracing for Windows (ETW) for the IIS 8.5 web server must be enabled.
New: Both the log file and Event Tracing for Windows (ETW) for the IIS 10.0 web server must be enabled.
---
SV-218787:
Old: An IIS 8.5 web server behind a load balancer or proxy server, must produce log records containing the source client IP and destination information.
New: An IIS 10.0 web server behind a load balancer or proxy server must produce log records containing the source client IP and destination information.
---
SV-218788:
Old: The IIS 8.5 web server must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 8.5 web server events.
New: The IIS 10.0 web server must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 10.0 web server events.
---
SV-218789:
Old: The IIS 8.5 web server must produce log records containing sufficient information to establish the identity of any user&#x2F;subject or process associated with an event.
New: The IIS 10.0 web server must produce log records containing sufficient information to establish the identity of any user&#x2F;subject or process associated with an event.
---
SV-218790:
Old: The log information from the IIS 8.5 web server must be protected from unauthorized modification or deletion.
New: The log information from the IIS 10.0 web server must be protected from unauthorized modification or deletion.
---
SV-218791:
Old: The log data and records from the IIS 8.5 web server must be backed up onto a different system or media.
New: The log data and records from the IIS 10.0 web server must be backed up onto a different system or media.
---
SV-218792:
Old: The IIS 8.5 web server must not perform user management for hosted applications.
New: The IIS 10.0 web server must not perform user management for hosted applications.
---
SV-218793:
Old: The IIS 8.5 web server must only contain functions necessary for operation.
New: The IIS 10.0 web server must only contain functions necessary for operation.
---
SV-218794:
Old: The IIS 8.5 web server must not be both a website server and a proxy server.
New: The IIS 10.0 web server must not be both a website server and a proxy server.
---
SV-218795:
Old: All IIS 8.5 web server sample code, example applications, and tutorials must be removed from a production IIS 8.5 server.
New: All IIS 10.0 web server sample code, example applications, and tutorials must be removed from a production IIS 10.0 server.
---
SV-218796:
Old: The accounts created by uninstalled features (i.e., tools, utilities, specific, etc.) must be deleted from the IIS 8.5 server.
New: The accounts created by uninstalled features (i.e., tools, utilities, specific, etc.) must be deleted from the IIS 10.0 server.
---
SV-218797:
Old: The IIS 8.5 web server must be reviewed on a regular basis to remove any Operating System features, utility programs, plug-ins, and modules not necessary for operation.
New: The IIS 10.0 web server must be reviewed on a regular basis to remove any Operating System features, utility programs, plug-ins, and modules not necessary for operation.
---
SV-218798:
Old: The IIS 8.5 web server must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.
New: The IIS 10.0 web server must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.
---
SV-218799:
Old: The IIS 8.5 web server must have Web Distributed Authoring and Versioning (WebDAV) disabled.
New: The IIS 10.0 web server must have Web Distributed Authoring and Versioning (WebDAV) disabled.
---
SV-218800:
Old: The IIS 8.5 web server must perform RFC 5280-compliant certification path validation.
New: The IIS 10.0 web server must perform RFC 5280-compliant certification path validation.
---
SV-218801:
Old: Java software installed on a production IIS 8.5 web server must be limited to .class files and the Java Virtual Machine.
New: Java software installed on a production IIS 10.0 web server must be limited to .class files and the Java Virtual Machine.
---
SV-218802:
Old: IIS 8.5 Web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.
New: IIS 10.0 Web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.
---
SV-218803:
Old: The IIS 8.5 web server must separate the hosted applications from hosted web server management functionality.
New: The IIS 10.0 web server must separate the hosted applications from hosted web server management functionality.
---
SV-218804:
Old: The IIS 8.5 web server must use cookies to track session state.
New: The IIS 10.0 web server must use cookies to track session state.
---
SV-218806:
Old: The IIS 8.5 web server must augment re-creation to a stable and known baseline.
New: The IIS 10.0 web server must augment re-creation to a stable and known baseline.
---
SV-218807:
Old: The production IIS 8.5 web server must utilize SHA2 encryption for the Machine Key.
New: The production IIS 10.0 web server must utilize SHA2 encryption for the Machine Key.
---
SV-218808:
Old: Directory Browsing on the IIS 8.5 web server must be disabled.
New: Directory Browsing on the IIS 10.0 web server must be disabled.
---
SV-218809:
Old: The IIS 8.5 web server Indexing must only index web content.
New: The IIS 10.0 web server Indexing must only index web content.
---
SV-218810:
Old: Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 8.5 web server, patches, loaded modules, and directory paths.
New: Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 10.0 web server, patches, loaded modules, and directory paths.
---
SV-218812:
Old: The IIS 8.5 web server must restrict inbound connections from nonsecure zones.
New: The IIS 10.0 web server must restrict inbound connections from non-secure zones.
---
SV-218813:
Old: The IIS 8.5 web server must provide the capability to immediately disconnect or disable remote access to the hosted applications.
New: The IIS 10.0 web server must provide the capability to immediately disconnect or disable remote access to the hosted applications.
---
SV-218814:
Old: IIS 8.5 web server system files must conform to minimum file permission requirements.
New: IIS 10.0 web server system files must conform to minimum file permission requirements.
---
SV-218815:
Old: The IIS 8.5 web server must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 8.5 web server.
New: The IIS 10.0 web server must use a logging mechanism configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 10.0 web server.
---
SV-218817:
Old: The IIS 8.5 web server must not be running on a system providing any other role.
New: The IIS 10.0 web server must not be running on a system providing any other role.
---
SV-218818:
Old: The Internet Printing Protocol (IPP) must be disabled on the IIS 8.5 web server.
New: The Internet Printing Protocol (IPP) must be disabled on the IIS 10.0 web server.
---
SV-218819:
Old: The IIS 8.5 web server must be tuned to handle the operational requirements of the hosted application.
New: The IIS 10.0 web server must be tuned to handle the operational requirements of the hosted application.
---
SV-218820:
Old: IIS 8.5 web server session IDs must be sent to the client using TLS.
New: IIS 10.0 web server session IDs must be sent to the client using TLS.
---
SV-218823:
Old: All accounts installed with the IIS 8.5 web server software and tools must have passwords assigned and default passwords changed.
New: All accounts installed with the IIS 10.0 web server software and tools must have passwords assigned and default passwords changed.
---
SV-218824:
Old: Unspecified file extensions on a production IIS 8.5 web server must be removed.
New: Unspecified file extensions on a production IIS 10.0 web server must be removed.
---
SV-218825:
Old: The IIS 8.5 web server must have a global authorization rule configured to restrict access.
New: The IIS 10.0 web server must have a global authorization rule configured to restrict access.
---
SV-218826:
Old: The IIS 8.5 MaxConnections setting must be configured to limit the number of allowed simultaneous session requests.
New: The IIS 10.0 websites MaxConnections setting must be configured to limit the number of allowed simultaneous session requests.
---
</details>

### Updated Descriptions
<details>
  <summary>Click to expand.</summary>
SV-218785:
Old:
```
Log files are a critical component to the successful management of an IS used within the DoD. By generating log files with useful information web administrators can leverage them in the event of a disaster, malicious attack, or other site specific needs.

Ascertaining the correct order of the events that occurred is important during forensic analysis. Events that appear harmless by themselves might be flagged as a potential threat when properly viewed in sequence. By also establishing the event date and time, an event can be properly viewed with an enterprise tool to fully see a possible threat in its entirety.

Without sufficient information establishing when the log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

```
New:
```
Log files are a critical component to the successful management of an IS used within the DoD. By generating log files with useful information, web administrators can leverage them in the event of a disaster, malicious attack, or other site specific needs.

Ascertaining the correct order of the events that occurred is important during forensic analysis. Events that appear harmless by themselves might be flagged as a potential threat when properly viewed in sequence. By also establishing the event date and time, an event can be properly viewed with an enterprise tool to fully see a possible threat in its entirety.

Without sufficient information establishing when the log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.



```
---
SV-218786:
Old:
```
Internet Information Services (IIS) on Windows Server 2012 provides basic logging capabilities. However, because IIS takes some time to flush logs to disk, administrators do not have access to logging information in real-time. In addition, text-based log files can be difficult and time-consuming to process.

In IIS 8.5, the administrator has the option of sending logging information to Event Tracing for Windows (ETW). This option gives the administrator the ability to use standard query tools, or create custom tools, for viewing real-time logging information in ETW. This provides a significant advantage over parsing text-based log files that are not updated in real time.

```
New:
```
Internet Information Services (IIS) on Windows Server 2012 provides basic logging capabilities. However, because IIS takes some time to flush logs to disk, administrators do not have access to logging information in real-time. In addition, text-based log files can be difficult and time-consuming to process.

In IIS 10.0, the administrator has the option of sending logging information to Event Tracing for Windows (ETW). This option gives the administrator the ability to use standard query tools, or create custom tools, for viewing real-time logging information in ETW. This provides a significant advantage over parsing text-based log files that are not updated in real time.



```
---
SV-218787:
Old:
```
Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct source, e.g. source IP, of the events is important during forensic analysis. Correctly determining the source of events will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the source occurred in other areas within the enterprise.

A web server behind a load balancer or proxy server, when not configured correctly, will record the load balancer or proxy server as the source of every logable event. When looking at the information forensically, this information is not helpful in the investigation of events. The web server must record with each event the client source of the event.

```
New:
```
Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct source (e.g., source IP), of the events is important during forensic analysis. Correctly determining the source of events will add information to the overall reconstruction of the loggable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the source occurred in other areas within the enterprise.

A web server behind a load balancer or proxy server, when not configured correctly, will record the load balancer or proxy server as the source of every loggable event. When looking at the information forensically, this information is not helpful in the investigation of events. The web server must record with each event the client source of the event.

```
---
SV-218788:
Old:
```
Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the success or failure of an event is important during forensic analysis. Correctly determining the outcome will add information to the overall reconstruction of the logable event. By determining the success or failure of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the event occurred in other areas within the enterprise.

Without sufficient information establishing the success or failure of the logged event, investigation into the cause of event is severely hindered. The success or failure also provides a means to measure the impact of an event and help authorized personnel to determine the appropriate response. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

```
New:
```
Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the success or failure of an event is important during forensic analysis. Correctly determining the outcome will add information to the overall reconstruction of the loggable event. By determining the success or failure of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the event occurred in other areas within the enterprise.

Without sufficient information establishing the success or failure of the logged event, investigation into the cause of event is severely hindered. The success or failure also provides a means to measure the impact of an event and help authorized personnel determine the appropriate response. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

```
---
SV-218790:
Old:
```
A major tool in exploring the website use, attempted use, unusual conditions, and problems are the access and error logs. In the event of a security incident, these logs can provide the SA and the web manager with valuable information. Failure to protect log files could enable an attacker to modify the log file data or falsify events to mask an attacker's activity.

```
New:
```
A major tool in exploring the website use, attempted use, unusual conditions, and problems are the access and error logs. In the event of a security incident, these logs can provide the System Administrator (SA) and the web manager with valuable information. Failure to protect log files could enable an attacker to modify the log file data or falsify events to mask an attacker's activity.



```
---
SV-218791:
Old:
```
Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to an unrelated system or onto separate media than the system the web server is actually running on helps to assure that, in the event of a catastrophic system failure, the log records will be retained.

```
New:
```
Protection of log data includes ensuring log data is not accidentally lost or deleted. Backing up log records to an unrelated system, or onto separate media than the system on which the web server is running, helps to ensure the log records will be retained in the event of a catastrophic system failure.

```
---
SV-218792:
Old:
```
User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks like password complexity, locking users after a configurable number of failed logons, and management of temporary and emergency accounts; and all of this must be done enterprise-wide.

The web server contains a minimal user management function, but the web server user management function does not offer enterprise-wide user management, and user management is not the primary function of the web server. User management for the hosted applications should be done through a facility that is built for enterprise-wide user management, like LDAP and Active Directory.

```
New:
```
User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks enterprise-wide, such as password complexity, locking users after a configurable number of failed logons, and management of temporary and emergency accounts.

The web server contains a minimal user management function, but the web server user management function does not offer enterprise-wide user management, and user management is not the primary function of the web server. User management for the hosted applications should be done through a facility built for enterprise-wide user management, such as LDAP and Active Directory.

```
---
SV-218793:
Old:
```
A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system.

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.

```
New:
```
A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system.

The web server must provide the capability to disable, uninstall, or deactivate functionality and services deemed non-essential to the web server mission or that adversely impact server performance.

```
---
SV-218794:
Old:
```
A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests into an otherwise protected network is a very common attack making the attack anonymous.

```
New:
```
A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that also proxy requests into an otherwise protected network is a common attack, making the attack anonymous.

```
---
SV-218796:
Old:
```
When accounts used for web server features such as documentation, sample code, example applications, tutorials, utilities, and services are created even though the feature is not installed, they become an exploitable threat to a web server.

These accounts become inactive, are not monitored through regular use, and passwords for the accounts are not created or updated. An attacker, through very little effort, can use these accounts to gain access to the web server and begin investigating ways to elevate the account privileges.

The accounts used for web server features not installed must not be created and must be deleted when these features are uninstalled.

```
New:
```
Accounts used for web server features such as documentation, sample code, example applications, tutorials, utilities, and services created when the feature is not installed, become an exploitable threat to a web server.

These accounts become inactive, are not monitored through regular use, and passwords for the accounts are not created or updated. An attacker, through very little effort, can use these accounts to gain access to the web server and begin investigating ways to elevate the account privileges.

The accounts used for web server features not installed must not be created and must be deleted when these features are uninstalled.

```
---
SV-218797:
Old:
```
Just as running unneeded services and protocols is a danger to the web server at the lower levels of the OSI model, running unneeded utilities and programs is also a danger at the application layer of the OSI model. Office suites, development tools, and graphical editors are examples of such programs that are troublesome.

Individual productivity tools have no legitimate place or use on an enterprise, production web server and they are also prone to their own security risks. The web server installation process must provide options allowing the installer to choose which utility programs, services, and modules are to be installed or removed. By having a process for installation and removal, the web server is guaranteed to be in a more stable and secure state than if these services and programs were installed and removed manually.

```
New:
```
Just as running unneeded services and protocols is a danger to the web server at the lower levels of the OSI model, running unneeded utilities and programs is a danger at the application layer of the OSI model. Office suites, development tools, and graphic editors are examples of such troublesome programs.

Individual productivity tools have no legitimate place or use on an enterprise production web server and are prone to security risks. The web server installation process must provide options allowing the installer to choose which utility programs, services, and modules are to be installed or removed. By having a process for installation and removal, the web server is guaranteed to be in a more stable and secure state than if these services and programs were installed and removed manually.

```
---
SV-218798:
Old:
```
Controlling what a user of a hosted application can access is part of the security posture of the web server. Any time a user can access more functionality than is needed for the operation of the hosted application poses a security issue. A user with too much access can view information that is not needed for the user's job role, or the user could use the function in an unintentional manner.

A MIME tells the web server what type of program, various file types, and extensions are and what external utilities or programs are needed to execute the file type.

A shell is a program that serves as the basic interface between the user and the operating system, so hosted application users must not have access to these programs. Shell programs may execute shell escapes and can then perform unauthorized activities that could damage the security posture of the web server.

```
New:
```
Controlling what a user of a hosted application can access is part of the security posture of the web server. Any time a user can access more functionality than is needed for the operation of the hosted application poses a security issue. A user with too much access can view information that is not needed for the user's job role, or the user could use the function in an unintentional manner.

A MIME tells the web server the type of program, various file types, and extensions and what external utilities or programs are needed to execute the file type.

A shell is a program that serves as the basic interface between the user and the operating system to ensure hosted application users do not have access to these programs. Shell programs may execute shell escapes and can perform unauthorized activities that could damage the security posture of the web server.

```
---
SV-218799:
Old:
```
A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.

```
New:
```
A web server can be installed with functionality that by its nature is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol which, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.

```
---
SV-218800:
Old:
```
This check verifies the server certificate is actually a DoD-issued certificate used by the organization being reviewed. This is used to verify the authenticity of the website to the user. If the certificate is not issued by the DoD or if the certificate has expired, then there is no assurance the use of the certificate is valid. The entire purpose of using a certificate is, therefore, compromised.

```
New:
```
This check verifies the server certificate is actually a DoD-issued certificate used by the organization being reviewed. This is used to verify the authenticity of the website to the user. If the certificate is not issued by the DoD or if the certificate has expired, then there is no assurance the use of the certificate is valid, and therefore; the entire purpose of using a certificate is compromised.

```
---
SV-218801:
Old:
```
Mobile code in hosted applications allows the developer to add functionality and displays to hosted applications that are fluid, as opposed to a static web page. The data presentation becomes more appealing to the user, is easier to analyze, and navigation through the hosted application and data is much less complicated.

Some mobile code technologies in use in today's applications are: Java, JavaScript, ActiveX, PDF, Postscript, Shockwave movies, Flash animations, and VBScript. The DoD has created policies that define the usage of mobile code on DoD systems. The usage restrictions and implementation guidance apply to both the selection and use of mobile code installed on organizational servers and mobile code downloaded and executed on individual workstations.

Source code for a Java program is, many times, stored in files with either .java or .jpp file extensions. From the .java and .jpp files the Java compiler produces a binary file with an extension of .class. The .java or .jpp file could therefore reveal sensitive information regarding an application's logic and permissions to resources on the server.

```
New:
```
Mobile code in hosted applications allows the developer to add functionality and displays to hosted applications that are fluid, as opposed to a static web page. The data presentation becomes more appealing to the user, is easier to analyze, and is less complicated to navigate through the hosted application and data.

Some mobile code technologies in use in today's applications are: Java, JavaScript, ActiveX, PDF, Postscript, Shockwave movies, Flash animations, and VBScript. The DoD has created policies that define the usage of mobile code on DoD systems. The usage restrictions and implementation guidance apply to both the selection and use of mobile code installed on organizational servers and mobile code downloaded and executed on individual workstations.

Source code for a Java program is often stored in files with either .java or .jpp file extensions. From the .java and .jpp files the Java compiler produces a binary file with an extension of .class. The .java or .jpp file could therefore reveal sensitive information regarding an application's logic and permissions to resources on the server.

```
---
SV-218804:
Old:
```
Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

Cookies associate session information with client information for the duration of a user’s connection to a website. Using cookies is a more efficient way to track session state than any of the methods that do not use cookies because cookies do not require any redirection.

```
New:
```
Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

Using URI will embed the session ID as a query string in the Uniform Resource Identifier (URI) request and then the URI is redirected to the originally requested URL. The changed URI request is used for the duration of the session, so no cookie is necessary.

By requiring expired session IDs to be regenerated while using URI, potential attackers have less time to capture a cookie and gain access to the Web server content.



```
---
SV-218808:
Old:
```
Directory browsing allows the contents of a directory to be displayed upon request from a web client. If directory browsing is enabled for a directory in IIS, users could receive a web page listing the contents of the directory. If directory browsing is enabled the risk of inadvertently disclosing sensitive content is increased.

```
New:
```
Directory browsing allows the contents of a directory to be displayed upon request from a web client. If directory browsing is enabled for a directory in IIS, users could receive a web page listing the contents of the directory. If directory browsing is enabled, the risk of inadvertently disclosing sensitive content is increased.

```
---
SV-218812:
Old:
```
Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be capable of restricting access from what the DoD defines as nonsecure zones. Nonsecure zones are defined as any IP, subnet, or region that is defined as a threat to the organization. The nonsecure zones must be defined for public web servers logically located in a DMZ, as well as private web servers with perimeter protection devices. By restricting access from nonsecure zones, through internal web server access list, the web server can stop or slow denial of service (DoS) attacks on the web server.

```
New:
```
Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be capable of restricting access from what the DoD defines as non-secure zones. Non-secure zones are defined as any IP, subnet, or region defined as a threat to the organization. The non-secure zones must be defined for public web servers logically located in a DMZ, as well as private web servers with perimeter protection devices. By restricting access from non-secure zones through internal web server access lists, the web server can stop or slow denial of service (DoS) attacks on the web server.

```
---
SV-218815:
Old:
```
In order to make certain that the logging mechanism used by the web server has sufficient storage capacity in which to write the logs, the logging mechanism needs to be able to allocate log record storage capacity.

The task of allocating log record storage capacity is usually performed during initial installation of the logging mechanism. The system administrator will usually coordinate the allocation of physical drive space with the web server administrator along with the physical location of the partition and disk. Refer to NIST SP 800-92 for specific requirements on log rotation and storage dependent on the impact of the web server.

```
New:
```
To ensure the logging mechanism used by the web server has sufficient storage capacity in which to write the logs, the logging mechanism must be able to allocate log record storage capacity.

The task of allocating log record storage capacity is usually performed during initial installation of the logging mechanism. The system administrator will usually coordinate the allocation of physical drive space with the web server administrator along with the physical location of the partition and disk. Refer to NIST SP 800-92 for specific requirements on log rotation and storage dependent on the impact of the web server.

```
---
SV-218816:
Old:
```
A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.

The key web service administrative and configuration tools must only be accessible by the web server staff. All users granted this authority will be documented and approved by the ISSO. Access to the IIS Manager will be limited to authorized users and administrators.

```
New:
```
A web server can be modified through parameter modification, patch installation, upgrades to the web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a DoS, web server instability, or hosted application instability.

To limit changes to the web server and limit exposure to any adverse effects from the changes, files such as the web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.

The key web service administrative and configuration tools must only be accessible by the web server staff. All users granted this authority will be documented and approved by the ISSO. Access to the IIS Manager will be limited to authorized users and administrators.



```
---
SV-218817:
Old:
```
Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system.

The web server must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability assessments.

```
New:
```
Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system.

The web server must provide the capability to disable or deactivate network-related services deemed non-essential to the server mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability assessments.

```
---
SV-218818:
Old:
```
The use of Internet Printing Protocol (IPP) on an IIS web server allows client’s access to shared printers. This privileged access could allow remote code execution by increasing the web servers attack surface. Additionally, since IPP does not support SSL, it is considered a risk and will not be deployed.

```
New:
```
The use of IPP on an IIS web server allows client access to shared printers. This privileged access could allow remote code execution by increasing the web servers attack surface. Additionally, since IPP does not support SSL, it is considered a risk and will not be deployed.

```
---
SV-218819:
Old:
```
A Denial of Service (DoS) can occur when the web server is so overwhelmed that it can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the web server must be tuned to handle the expected traffic for the hosted applications.

```
New:
```
A Denial of Service (DoS) can occur when the web server is overwhelmed and can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the web server must be tuned to handle the expected traffic for the hosted applications.

```
---
SV-218820:
Old:
```
The HTTP protocol is a stateless protocol. To maintain a session, a session identifier is used. The session identifier is a piece of data that is used to identify a session and a user. If the session identifier is compromised by an attacker, the session can be hijacked. By encrypting the session identifier, the identifier becomes more difficult for an attacker to hijack, decrypt, and use before the session has expired.

```
New:
```
The HTTP protocol is a stateless protocol. To maintain a session, a session identifier is used. The session identifier is a piece of data used to identify a session and a user. If the session identifier is compromised by an attacker, the session can be hijacked. By encrypting the session identifier, the identifier becomes more difficult for an attacker to hijack, decrypt, and use before the session has expired.

```
---
SV-218826:
Old:
```
Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a website, facilitating a Denial of Service attack. Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests per IP address and may include, where feasible, limiting parameter values associated with keepalive (i.e., a parameter used to limit the amount of time a connection may be inactive).

```
New:
```
Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a website, facilitating a Denial of Service (DoS) attack. Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests per IP address and may include, where feasible, limiting parameter values associated with keepalive (i.e., a parameter used to limit the amount of time a connection may be inactive).

```
---
</details>