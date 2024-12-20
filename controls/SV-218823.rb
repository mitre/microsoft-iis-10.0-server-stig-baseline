control 'SV-218823' do
  title 'All accounts installed with the IIS 10.0 web server software and tools must have passwords assigned and default passwords changed.'
  desc 'During installation of the web server software, accounts are created for the web server to operate properly. The accounts installed can have either no password installed or a default password, which will be known and documented by the vendor and the user community.

The first things an attacker will try when presented with a logon screen are the default user identifiers with default passwords. Installed applications may also install accounts with no password, making the logon even easier. Once the web server is installed, the passwords for any created accounts should be changed and documented. The new passwords must meet the requirements for all passwords, i.e., upper/lower characters, numbers, special characters, time until change, reuse policy, etc.

Service accounts or system accounts that have no logon capability do not need to have passwords set or changed.'
  desc 'check', 'Access the IIS 10.0 web server.

Access the "Apps" menu. Under "Administrative Tools", select "Computer Management".

In left pane, expand "Local Users and Groups" and click "Users".

Review the local users listed in the middle pane. 

If any local accounts are present and used by IIS 10.0, verify with System Administrator that default passwords have been changed.

If passwords have not been changed from the default, this is a finding.'
  desc 'fix', 'Access the IIS 10.0 web server.

Access the "Apps" menu. Under Administrative Tools, select Computer Management.

In left pane, expand "Local Users and Groups" and click on "Users".

Change passwords for any local accounts present that are used by IIS 10.0, then verify with System Administrator default passwords have been changed.

Develop an internal process for changing passwords on a regular basis.'
  impact 0.7
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag gtitle: 'SRG-APP-000516-WSR-000079'
  tag gid: 'V-218823'
  tag rid: 'SV-218823r961863_rule'
  tag stig_id: 'IIST-SV-000156'
  tag fix_id: 'F-20293r310945_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
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

  describe 'This test currently has no automated tests, you must check manually' do
    skip 'This check must be preformed manually'
  end
end
