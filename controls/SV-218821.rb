control 'SV-218821' do
  title 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved Transport Layer Security (TLS) version.'
  desc 'TLS encryption is a required security setting for a private web server. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. A private web server must use a FIPS 140-2-approved TLS version, and all non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Access the IIS 10.0 Web Server.

Navigate to:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server

Verify a REG_DWORD value of "0" for "DisabledByDefault".
Verify a REG_DWORD value of "1" for "Enabled".

Navigate to:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server

Verify a REG_DWORD value of "1" for "DisabledByDefault".
Verify a REG_DWORD value of "0" for "Enabled".

If any of the respective registry paths do not exist or are configured with the wrong value, this is a finding.'
  desc 'fix', 'Access the IIS 10.0 Web Server.

Navigate to:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server 

Create a REG_DWORD named "DisabledByDefault" with a value of "0".
Create a REG_DWORD named "Enabled" with a  value of "1".

Navigate to:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server

For each protocol:
Create a REG_DWORD named "DisabledByDefault" with a value of "1".
Create a REG_DWORD named "Enabled" with a  value of "0".'
  impact 0.7
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20293r903104_chk'
  tag severity: 'high'
  tag gid: 'V-218821'
  tag rid: 'SV-218821r961632_rule'
  tag stig_id: 'IIST-SV-000153'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-20291r903105_fix'
  tag 'documentable'
  tag legacy: ['SV-109281', 'V-100177']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  tls1_2Disabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client').DisabledByDefault == 0
  tls1_2Enabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client').Enabled == 1
  
  tls1_0Disabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client').DisabledByDefault == 1
  tls1_0Enabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client').Enabled == 0
  tls1_1Disabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client').DisabledByDefault == 1
  tls1_1Enabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client').Enabled == 0
  ssl2_0Disabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').DisabledByDefault == 1
  ssl2_0Enabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').Enabled == 0
  ssl3_0Disabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client').DisabledByDefault == 1
  ssl3_0Enabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client').Enabled == 0

  
  describe 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, TLS 1.2 should be DisabledByDefault. (currently: TLS 1.2 ' + (tls1_2Disabled ? 'is not DisabledByDefault' : 'is DisabledByDefault') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client').DisabledByDefault }
    it 'TLS 1.2 DisabledByDefault should eq 0' do
      expect(subject).to cmp('0')
    end
  end
  describe 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, TLS 1.2 should be Enabled. (currently: TLS 1.2 ' + (tls1_2Enabled ? 'is Enabled' : 'is not Enabled') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client').Enabled }
    it 'TLS 1.2 Enabled should eq 1' do
      expect(subject).to cmp('1')
    end
  end

  describe 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, TLS 1.0 should be DisabledByDefault. (currently: TLS 1.0 ' + (tls1_0Disabled ? 'is DisabledByDefault' : 'is not DisabledByDefault') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client').DisabledByDefault }
    it 'TLS 1.0 DisabledByDefault should eq 1' do
      expect(subject).to cmp('1')
    end
  end
  describe 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, TLS 1.0 should not be Enabled. (currently: TLS 1.0 ' + (tls1_0Enabled ? 'is not Enabled' : 'is Enabled') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client').Enabled }
    it 'TLS 1.0 Enabled should eq 0' do
      expect(subject).to cmp('0')
    end
  end

  describe 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, TLS 1.1 should be DisabledByDefault. (currently: TLS 1.1 ' + (tls1_1Disabled ? 'is DisabledByDefault' : 'is not DisabledByDefault') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client').DisabledByDefault }
    it 'TLS 1.1 DisabledByDefault should eq 1' do
      expect(subject).to cmp('1')
    end
  end
  describe 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, TLS 1.1 should not be Enabled. (currently: TLS 1.1 ' + (tls1_1Enabled ? 'is not Enabled' : 'is Enabled') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client').Enabled }
    it 'TLS 1.1 Enabled should eq 0' do
      expect(subject).to cmp('0')
    end
  end

  describe 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, SSL 2.0 should be DisabledByDefault. (currently: SSL 2.0 ' + (ssl2_0Disabled ? 'is DisabledByDefault' : 'is not DisabledByDefault') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').DisabledByDefault }
    it 'SSL 2.0 DisabledByDefault should eq 1' do
      expect(subject).to cmp('1')
    end
  end
  describe 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, SSL 2.0 should not be Enabled. (currently: SSL 2.0 ' + (ssl2_0Enabled ? 'is not Enabled' : 'is Enabled') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').Enabled }
    it 'SSL 2.0 Enabled should eq 0' do
      expect(subject).to cmp('0')
    end
  end

  describe 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, SSL 3.0 should be DisabledByDefault. (currently: SSL 3.0 ' + (ssl3_0Disabled ? 'is DisabledByDefault' : 'is not DisabledByDefault') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client').DisabledByDefault }
    it 'SSL 3.0 DisabledByDefault should eq 1' do
      expect(subject).to cmp('1')
    end
  end
  describe 'An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, SSL 3.0 should not be Enabled. (currently: SSL 3.0 ' + (ssl3_0Enabled ? 'is not Enabled' : 'is Enabled') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client').Enabled }
    it 'SSL 3.0 Enabled should eq 0' do
      expect(subject).to cmp('0')
    end
  end
end
