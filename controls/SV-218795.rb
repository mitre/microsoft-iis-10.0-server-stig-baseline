control 'SV-218795' do
  title 'All IIS 10.0 web server sample code, example applications, and tutorials must be removed from a production IIS 10.0 server.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server. A production web server may only contain components that are operationally necessary (i.e., compiled code, scripts, web content, etc.). Delete all directories containing samples and any scripts used to execute the samples.'
  desc 'check', 'Navigate to the following folders:

inetpub\\
Program Files\\Common Files\\System\\msadc
Program Files (x86)\\Common Files\\System\\msadc

If the folder or sub-folders contain any executable sample code, example applications, or tutorials which are not explicitly used by a production website, this is a finding.'
  desc 'fix', 'Remove any executable sample code, example applications, or tutorials which are not explicitly used by a production website.'
  impact 0.7
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20267r310860_chk'
  tag severity: 'high'
  tag gid: 'V-218795'
  tag rid: 'SV-218795r960963_rule'
  tag stig_id: 'IIST-SV-000120'
  tag gtitle: 'SRG-APP-000141-WSR-000077'
  tag fix_id: 'F-20265r310861_fix'
  tag 'documentable'
  tag legacy: ['SV-109229', 'V-100125']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe windows_feature('Web-Server') do
    it { should be_installed }
  end

  describe windows_feature('Web-WebServer') do
    it { should be_installed }
  end
  describe windows_feature('Web-Common-Http') do
    it { should be_installed }
  end

  webroot_folder_test = command('(Get-Item C:\inetpub) -is [System.IO.DirectoryInfo]').stdout.strip
  webroot_found = webroot_folder_test == '' || webroot_folder_test == 'False' ? false : true

  describe 'Able to access webroot at C:\\inetpub ' do
    subject { webroot_found }
    it { should be true }
  end


  # Checking for Executable File Signature
  if attribute('disable_slow_controls')
    describe "This control consistently takes a long time to run and has been disabled
      using the disable_slow_controls attribute." do
      skip "This control consistently takes a long time to run and has been disabled
            using the disable_slow_controls attribute. You must enable this control for a
            full accreditation for production."
    end
  else
    C_Inetpub_two_bytes = command('Get-ChildItem -Path "C:\Inetpub" -Recurse | ForEach { if ( $_ -is [System.IO.FileInfo] ) {-join ([char[]](Get-Content  $_.FullName -Encoding byte -TotalCount 2))} }').stdout.strip.split("\r\n")
    C_Program_Files_Common_Files_System_msadc_two_bytes = command('Get-ChildItem -Path "C:\Program Files\Common Files\System\msadc" -Recurse | ForEach { if ( $_ -is [System.IO.FileInfo] ) {-join ([char[]](Get-Content  $_.FullName -Encoding byte -TotalCount 2))} }').stdout.strip.split("\r\n")
    C_Program_Files_x86_Common_Files_System_msadc_two_bytes = command('Get-ChildItem -Path "C:\Program Files (x86)\Common Files\System\msadc" -Recurse | ForEach { if ( $_ -is [System.IO.FileInfo] ) {-join ([char[]](Get-Content  $_.FullName -Encoding byte -TotalCount 2))} }').stdout.strip.split("\r\n")

    C_Inetpub_FileExtentions = command('Get-ChildItem -Path "C:\Inetpub" -Recurse | ForEach { if ( $_ -is [System.IO.FileInfo] ) {-join (  ([System.IO.FileInfo]$_.FullName).Extension ) } }').stdout.strip.split("\r\n")
    C_Program_Files_Common_Files_System_msadc_FileExtensions = command('Get-ChildItem -Path "C:\Program Files\Common Files\System\msadc" -Recurse | ForEach { if ( $_ -is [System.IO.FileInfo] ) {-join (  ([System.IO.FileInfo]$_.FullName).Extension ) } }').stdout.strip.split("\r\n")
    C_Program_Files_x86_Common_Files_System_msadc_FileExtensions = command('Get-ChildItem -Path "C:\Program Files (x86)\Common Files\System\msadc" -Recurse | ForEach { if ( $_ -is [System.IO.FileInfo] ) {-join (  ([System.IO.FileInfo]$_.FullName).Extension ) } }').stdout.strip.split("\r\n")

    # Check of any of the files are executable
    describe 'Executable files found at C:\\Inetpub as File Signatures ' do
      subject { C_Inetpub_two_bytes }
      it { should_not include 'MZ' }
    end

    describe 'Executable files found at C:\\Program Files\\Common Files\\System\\msadc as File Signatures ' do
      subject { C_Program_Files_Common_Files_System_msadc_two_bytes }
      it { should_not include 'MZ' }
    end

    describe 'Executable files found at C:\\Program Files (x86)\\Common Files\\System\\msadc as File Signatures ' do
      subject { C_Program_Files_x86_Common_Files_System_msadc_two_bytes }
      it { should_not include 'MZ' }
    end

    # Check for known bad extensions
    describe 'Executable files found at C:\\Inetpub as File Signatures ' do
      subject { C_Inetpub_FileExtentions }
      it { should_not include 'ASP' }
      it { should_not include 'ASPX' }
      it { should_not include 'PHP' }
      it { should_not include 'DLL' }
      it { should_not include 'EXE' }
      it { should_not include 'HTM' }
      it { should_not include 'HTML' }
    end

    describe 'Executable files found at C:\\Program Files\\Common Files\\System\\msadc as as File Signatures ' do
      subject { C_Program_Files_Common_Files_System_msadc_FileExtensions }
      it { should_not include 'ASP' }
      it { should_not include 'ASPX' }
      it { should_not include 'PHP' }
      it { should_not include 'DLL' }
      it { should_not include 'EXE' }
      it { should_not include 'HTM' }
      it { should_not include 'HTML' }
    end

    describe 'Executable files found at C:\\Program Files (x86)\\Common Files\\System\\msadc as File Signatures ' do
      subject { C_Program_Files_x86_Common_Files_System_msadc_FileExtensions }
      it { should_not include 'ASP' }
      it { should_not include 'ASPX' }
      it { should_not include 'PHP' }
      it { should_not include 'DLL' }
      it { should_not include 'EXE' }
      it { should_not include 'HTM' }
      it { should_not include 'HTML' }
    end
  end
end
