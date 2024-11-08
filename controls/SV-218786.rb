control 'SV-218786' do
  title 'Both the log file and Event Tracing for Windows (ETW) for the IIS 10.0 web server must be enabled.'
  desc 'Internet Information Services (IIS) on Windows Server 2012 provides basic logging capabilities. However, because IIS takes some time to flush logs to disk, administrators do not have access to logging information in real-time. In addition, text-based log files can be difficult and time-consuming to process.

In IIS 10.0, the administrator has the option of sending logging information to Event Tracing for Windows (ETW). This option gives the administrator the ability to use standard query tools, or create custom tools, for viewing real-time logging information in ETW. This provides a significant advantage over parsing text-based log files that are not updated in real time.'
  desc 'check', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 server name.

Click the "Logging" icon.

Under Log Event Destination, verify the "Both log file and ETW event" radio button is selected.

If the "Both log file and ETW event" radio button is not selected, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 server name.

Click the "Logging" icon.

Under Log Event Destination, select the "Both log file and ETW event" radio button.

Under the "Actions" pane, click "Apply".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag gtitle: 'SRG-APP-000092-WSR-000055'
  tag satisfies: ['SRG-APP-000092-WSR-000055', 'SRG-APP-000108-WSR-000166', 'SRG-APP-000358-WSR-000063']
  tag gid: 'V-218786'
  tag rid: 'SV-218786r960888_rule'
  tag stig_id: 'IIST-SV-000103'
  tag fix_id: 'F-20256r310834_fix'
  tag cci: ['CCI-000139', 'CCI-001464', 'CCI-001851']
  tag nist: ['AU-5 a', 'AU-14 (1)', 'AU-4 (1)']
  tag 'false_negatives'
  tag 'false_positives'
  tag 'documentable'
  tag 'mitigations'
  tag 'severity_override_guidance'
  tag 'potential_impacts'
  tag 'third_party_tools'
  tag 'mitigation_controls'
  tag 'responsibility'
  tag 'ia_controls'
  tag 'check'
  tag 'fix'

  describe windows_feature('Web-Server') do
    it { should be_installed }
  end
  describe windows_feature('Web-WebServer') do
    it { should be_installed }
  end
  describe windows_feature('Web-Common-Http') do
    it { should be_installed }
  end

  iis_modules = command('Get-WebConfiguration  system.webServer/globalModules/*').stdout.strip

  describe 'Is required IIS Module for ETW (Tracing) installed ' do
    subject { iis_modules }
    it { should include 'TracingModule' }
  end

  iis_logging_configuration = command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "System.Applicationhost/Sites/SiteDefaults/logfile"  -name logTargetW3C').stdout.strip.split(',')

  describe 'IIS Logging configuration   ' do
    subject { iis_logging_configuration }
    it { should include 'File' }
    it { should include 'ETW' }
  end
end
