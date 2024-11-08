control 'SV-218806' do
  title 'The IIS 10.0 web server must augment re-creation to a stable and known baseline.'
  desc 'Making certain that the web server has not been updated by an unauthorized user is always a concern. Adding patches, functions, and modules that are untested and not part of the baseline opens the possibility for security risks. The web server must offer, and not hinder, a method that allows for the quick and easy reinstallation of a verified and patched baseline to guarantee the production web server is up-to-date and has not been modified to add functionality or expose security risks.

When the web server does not offer a method to roll back to a clean baseline, external methods, such as a baseline snapshot or virtualizing the web server, can be used.'
  desc 'check', 'Interview the System Administrator for the IIS 10.0 web server.

Ask for documentation on the disaster recovery methods tested and planned for the IIS 10.0 web server in the event of the necessity for rollback.

If documentation for a disaster recovery has not been established, this is a finding.'
  desc 'fix', 'Prepare documentation for disaster recovery methods for the IIS 10.0 web server in the event of the necessity for rollback.

Document and test the disaster recovery methods designed.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag gtitle: 'SRG-APP-000225-WSR-000074'
  tag gid: 'V-218806'
  tag rid: 'SV-218806r961122_rule'
  tag stig_id: 'IIST-SV-000136'
  tag fix_id: 'F-20276r310894_fix'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
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

  describe 'Manual review of DR portion of BCDR is required.' do
    skip 'Manual review of DR portion of BCDR is required.'
  end
end
