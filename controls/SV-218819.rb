control 'SV-218819' do
  title 'The IIS 10.0 web server must be tuned to handle the operational requirements of the hosted application.'
  desc 'A Denial of Service (DoS) can occur when the web server is overwhelmed and can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the web server must be tuned to handle the expected traffic for the hosted applications.'
  desc 'check', 'If the IIS 10.0 web server is not hosting any applications, this is Not Applicable.

If the IIS 10.0 web server is hosting applications, consult with the System Administrator to determine risk analysis performed when the application was written and deployed to the IIS 10.0 web server.

Obtain documentation on the configuration.

Verify, at a minimum, the following tuning settings in the registry.

Access the IIS 10.0 web server registry.

Verify the following keys are present and configured. The required setting depends upon the requirements of the application. 

Recommended settings are not provided as these settings must be explicitly configured to show a conscientious tuning has been made.

Navigate to HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\
"URIEnableCache"
"UriMaxUriBytes"
"UriScavengerPeriod"

If explicit settings are not configured for "URIEnableCache", "UriMaxUriBytes" and "UriScavengerPeriod", this is a finding.'
  desc 'fix', 'Access the IIS 10.0 web server registry.

Verify the following keys are present and configured. The required setting depends upon the requirements of the application. These settings must be explicitly configured to show a conscientious tuning has been made.

Navigate to HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\

Configure the following registry keys to levels to accommodate the hosted applications.

"URIEnableCache"
"UriMaxUriBytes"
"UriScavengerPeriod"'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag gtitle: 'SRG-APP-000435-WSR-000148'
  tag gid: 'V-218819'
  tag rid: 'SV-218819r961620_rule'
  tag stig_id: 'IIST-SV-000151'
  tag fix_id: 'F-20289r310933_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5', 'SC-5 a']
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

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP\Parameters') do
    its('URIEnableCache') { should_not eq nil }
    its('UriMaxUriBytes') { should_not eq nil }
    its('UriScavengerPeriod') { should_not eq nil }
  end
end
