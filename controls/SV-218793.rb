control 'SV-218793' do
  title 'The IIS 10.0 web server must only contain functions necessary for operation.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system.

The web server must provide the capability to disable, uninstall, or deactivate functionality and services deemed non-essential to the web server mission or that adversely impact server performance.'
  desc 'check', 'Click “Start”.

Open Control Panel.

Click “Programs”.

Click “Programs and Features”.

Review the installed programs. If any programs are installed other than those required for the IIS 10.0 web services, this is a finding.

Note: If additional software is needed, supporting documentation must be signed by the ISSO.'
  desc 'fix', 'Remove all unapproved programs and roles from the production IIS 10.0 web server.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag gid: 'V-218793'
  tag rid: 'SV-218793r960963_rule'
  tag stig_id: 'IIST-SV-000118'
  tag fix_id: 'F-20263r310855_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
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

  describe "The IIS 8.5 web server must only contain functions necessary for
  operation." do
    skip 'Manual review required for this control'
  end
end
