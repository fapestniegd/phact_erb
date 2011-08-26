#!/usr/bin/ruby
################################################################################
# dependency paths

# where our debian package puts netaddr
$:.push('/var/lib/gems/1.8/gems/netaddr-1.5.0/lib/') if File.directory?('/var/lib/gems/1.8/gems/netaddr-1.5.0/lib/')

# where the relative path to netaddr in our git repo:
oldwd = Dir.getwd
Dir.chdir(File.dirname($0))
$:.push([Dir.getwd,"lib/netaddr/lib"].join('/')) if File.directory?([Dir.getwd,"lib/netaddr/lib"].join('/'))
Dir.chdir(oldwd)

################################################################################
# external facts we can use to populate erbs
################################################################################
class PhactERB
  ################################################################################
  # "phacts"                                                                     #
  def fqdn
    begin
      begin
        require 'socket'
      rescue LoadError
          out = IO.popen('hostname -f') do |io|
            @fqdn = io.read
          end
          return @fqdn.chomp
      end
      @fqdn = Socket.gethostname
      return @fqdn.chomp
    end
  end

  def smeg
    begin
       require 'smeg'
    rescue
       put 'no smeg, sry.'
    end
  end
  
  def hostname
    begin
      @hostname = self.fqdn
      @hostname.sub!(/\..*/, '')
      return @hostname
    end
  end
  
  def domainname
    begin
      @self_domain = self.fqdn
      @self_domain.sub!(/^[^.]+\./, '')
    end
  end
  
  def basedn
    begin
      self_basedn = self.domainname
      self_basedn.gsub!(/\./, ',dc=')
      self_basedn = [ "dc=",self_basedn ].join
    end
  end
  
  def secret
    begin
      @secret = ''
      out = IO.popen('secret') do |io|
        @secret = io.read
      end
      return @secret
    end
  end

  def dig( record, type )
    #pp fuck =  { :record => record, :type => type }
    result = []
    begin
      require 'resolv'
    rescue LoadError
      warn 'DNS support may not be available due to missing resolv library'
      return nil
    end
    @domain = self.domainname
    @ncdata = {}
    @dns_res = Resolv::DNS.new('/etc/resolv.conf');
    #@dns_res = Resolv::DNS.new(:nameserver => ['8.8.8.8','8.8.4.4'], :search => [ @domain ], :ndots => 1)
    case type
      ##########################################################################
      when 'SOA'
        @dns_res.each_resource( record, Resolv::DNS::Resource::IN::ANY ) do | response |
            @type = response.class.to_s
            @type.sub!(/.*::/, '')
            if @type == type
                result.push({
                              :expire => response.expire,
                              :minimum => response.minimum,
                              :mname => response.mname.to_s,
                              :refresh => response.refresh,
                              :retry => response.retry,
                              :rname => response.rname.to_s,
                              :serial => response.serial,
                           });
            end
        end
        return result
      ##########################################################################
      when 'A'
        @dns_res.each_resource( record, Resolv::DNS::Resource::IN::ANY ) do | response |
            @type = response.class.to_s
            @type.sub!(/.*::/, '')
            if @type == type
                result.push(response.address.to_s)
            end
        end
        return result
      ##########################################################################
      when 'NS'
        @dns_res.each_resource( record, Resolv::DNS::Resource::IN::ANY ) do | response |
            @type = response.class.to_s
            @type.sub!(/.*::/, '')
            if @type == type
                result.push(response.name.to_s)
            end
        end
        return result
      ##########################################################################
      when 'SRV'
        h = {}
        @dns_res.each_resource( record, Resolv::DNS::Resource::IN::ANY ) do | response |
            @type = response.class.to_s
            @type.sub!(/.*::/, '')
            if @type == type
                h[response.priority] = [] unless  h[response.priority]
                h[response.priority].push({ 
                                            :server => response.target.to_s,
                                            :port => response.port,
                                          });
            end
        end
        h.keys.sort.each do | key |
           h[key].each do | srv |
               result.push(srv)
           end
        end
        return result
      ##########################################################################
      when 'MX'
        h = {}
        @dns_res.each_resource( record, Resolv::DNS::Resource::IN::ANY ) do | response |
            @type = response.class.to_s
            @type.sub!(/.*::/, '')
            if @type == type
                h[response.preference] = [] unless  h[response.preference]
                h[response.preference].push(response.exchange.to_s)
            end
        end
        h.keys.sort.each do | key |
           h[key].each do | mx |
               result.push(mx)
           end
        end
        return result
      ##########################################################################
      when 'PTR'
        @dns_res.each_name( record ) do | response |
            @type = response.class.to_s
            result.push(response.to_s)
        end
        return result
      ##########################################################################
      else
        warn [ "unsupported record type: [", type, "]" ].join('')
        return []
    end
  end

  def binddn
    return [ 'cn=',self.hostname,',ou=Hosts,',self.basedn ].join('') 
  end

  def bindpw
    return self.secret
  end

  def lsearch(basedn,filter,attrs)
    result = {}
    begin
      require 'ldap'
    rescue LoadError
      warn 'ldap operations will fail due to missing ldap library'
      return nil
    end 
    domain = self.domainname
    ldaps = self.dig(['_ldaps._tcp',domain].join('.'),'SRV' )
    connection = ldaps.shift
    conn = LDAP::SSLConn.new( connection.fetch(:server), connection.fetch(:port) )
    bound = conn.bind(self.binddn, self.bindpw)
    bound.search(basedn, LDAP::LDAP_SCOPE_SUBTREE, filter ) do | entry |
        attrs.each do | attr | 
          result[attr] = entry[attr]
        end
    end
    return result
  end

  def ifconfig
    ifcfg = []
    iface = {}
    begin
      out = IO.popen('/sbin/ifconfig') do |io|
        ifconfig_raw = io.read
        @ifconfig = ifconfig_raw.split(/\n/)
        @ifconfig.each do | line |
            line.sub!(/\s+$/,'');
            if match = line.scan(/(^[a-z0-9]+)\s+Link encap:(.*)/)[0 .. 1][0]
              if iface[:name]
                  ifcfg.push( iface.clone )
              end
              iface[:name] = match[0]
              iface[:encap] = match[1]
              if match = iface[:encap].scan(/(Ethernet)  HWaddr (\S+)/)[0..1][0]
                iface[:encap] = match[0]
                iface[:hwaddr] = match[1]
              end
            elsif match = line.scan(/inet addr:(\S+)\s+Bcast:(\S+)\s+Mask:(\S+)/)[0 .. 2][0]
              iface[:ipv4] = match[0]
              iface[:bcast] = match[1]
              iface[:netmask] = match[2]
            elsif match = line.scan(/inet6 addr: (.*) Scope:(.*)/)[0 .. 2][0]
              iface[:ipv6] = match[0]
              iface[:scope] = match[1]
            elsif match = line.scan(/(\S.*\S)\s+MTU:([0-9]+)\s+Metric:(.*)/)[0 .. 2][0]
              iface[:flags] = match[0].split(/\s+/)
              iface[:mtu] = match[1]
              iface[:metric] = match[2]
            elsif match = line.scan(/RX packets:([0-9]+) errors:([0-9]+) dropped:([0-9]+) overruns:([0-9]+) frame:([0-9]+)/)[0..4][0]
              iface[:rx_packets] = match[0]
              iface[:rx_errors] = match[1]
              iface[:rx_dropped] = match[2]
              iface[:rx_overruns] = match[3]
              iface[:rx_frame] = match[4]
            elsif match = line.scan(/TX packets:([0-9]+) errors:([0-9]+) dropped:([0-9]+) overruns:([0-9]+) carrier:([0-9]+)/)[0..4][0]
              iface[:tx_packets] = match[0]
              iface[:tx_errors] = match[1]
              iface[:tx_dropped] = match[2]
              iface[:tx_overruns] = match[3]
              iface[:tx_frame] = match[4]
            elsif match = line.scan(/collisions:([0-9]+) txqueuelen:([0-9]+) /)[0..1][0]
              iface[:collisions] = match[0]
              iface[:txqueuelen] = match[1]
            elsif match = line.scan(/RX bytes:([0-9]+) \((\S+ GB)\)  TX bytes:([0-9]+) \((\S+ GB)\)/)[0..3][0]
              iface[:rx_bytes] = match[0]
              iface[:rx_bytes_h] = match[1]
              iface[:tx_bytes] = match[2]
              iface[:tx_bytes_h] = match[3]
            elsif match = line.scan(/Interrupt:([0-9]+) Base address:(\S+)/)[0..1][0]
              iface[:interrupt] = match[0]
              iface[:base_address] = match[1]
            end
        end
        if iface[:name]
          ifcfg.push( iface.clone )
        end
      end
      return ifcfg
    end
  end

  def route
    rtable = []
    begin
      out = IO.popen('/sbin/route -n') do |io|
        routes_raw = io.read
        @route = routes_raw.split(/\n/)
        @route.each do | line |
          line.sub!(/\s+$/,'');
            if match = line.scan(/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([A-Z]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+(\S+)/)[0 .. 7][0]
              rtable.push({
                            :destination => match[0],
                            :gateway     => match[1],
                            :genmask     => match[2],
                            :flags       => match[3],
                            :metric      => match[4],
                            :ref         => match[5],
                            :use         => match[6],
                            :iface       => match[7],
                          });
            end
        end
      end
    end
    return rtable
  end

  def default_route
      self.route.each do | route |
          if route[:destination] == '0.0.0.0'
            return route[:gateway]
          end
      end
  end

  def default_iface
      self.route.each do | route |
          if route[:destination] == '0.0.0.0'
            return route[:iface]
          end
      end
  end

  def default_ipaddress
      self.route.each do | route |
          if route[:destination] == '0.0.0.0'
            name = route[:iface]
            self.ifconfig.each do | interface |
              if name == interface[:name]
                 return interface[:ipv4]
              end
            end
            #return interfaces.fetch(interface).fetch('ipv4')
          end
      end
  end

  def imma_ldap_server
      self.dig(['_ldaps._tcp',self.domainname].join('.'),'SRV' ).each do | srv |
        if srv[:server] == self.fqdn
          return true
        end
      end
      return false
  end

  def vpn_peer_ip(peer_dn)
    peer_parts = peer_dn.split(',')
    filter = peer_parts.shift
    basedn = peer_parts.join(',')
    self.lsearch( basedn, filter, ['ipHostNumber'] ).fetch('ipHostNumber').each do | ip |
        return ip unless self.is_rfc1918(ip) 
    end
  end

  def vpn_peer_hostname(peer_dn)
    peer_parts = peer_dn.split(',')
    hostname = peer_parts.shift.sub(/^cn=/,'')
    host_ou = peer_parts.shift
    domain = peer_parts.join(',').gsub(',dc=','.').sub(/^dc=/,'')
    return [hostname, domain].join('.')
  end
  
  def is_rfc1918(ip_address)
    begin
      require 'netaddr'
    rescue LoadError
      warn 'IP functions will not be accurate due to the missing netaddr.rb library'
      return false
    end  
    ipcidr4 = NetAddr::CIDR.create(ip_address)
    cidr_8 = NetAddr::CIDR.create('10.0.0.0/8')
    if cidr_8.contains?(ipcidr4)
      return true
    end
    cidr_12 = NetAddr::CIDR.create('172.16.0.0/12')
    if cidr_12.contains?(ipcidr4)
      return true
    end
    cidr_16 = NetAddr::CIDR.create('192.168.0.0/16')
    if cidr_16.contains?(ipcidr4)
      return true
    end
    return false
  end

  def vpn_private_ipaddress(peer_dn)
    peer_parts = peer_dn.split(',')
    filter = peer_parts.shift
    basedn = peer_parts.join(',')
    self.lsearch( basedn, filter, ['ipHostNumber'] ).fetch('ipHostNumber').sort.each do | ip |
      if self.is_rfc1918(ip) 
        return ip 
      end
    end
  end

  def vpn_data(domain)
    begin
      require 'netaddr'
    rescue LoadError
      warn 'IP functions will not be accurate due to the missing netaddr library'
      return false
    end  
    @vpndata = []
    peers = self.lsearch( 
                          ["ou=VPNs,ou=Sets,",self.basedn].join,  # search base
                          ["(cn=",domain,")"].join ,     # filter
                          ["uniqueMember"]
                     ).fetch("uniqueMember").each do | peer_dn |
       dnparts = peer_dn.split(/,/)
       filter = dnparts.shift
       searchbase = dnparts.join(',')
       ou_part = dnparts.shift
       domain = dnparts.join(',').gsub(',dc=','.').gsub(/^dc=/,'')
       hostname = filter.clone.sub!(/.*=/,'')
       fqdn = [ hostname, domain ].join('.')
       rwarriors = self.lsearch( 
                                    ["ou=Networks,",self.basedn].join, 
                                    ["(cn=",hostname,"-vpn-anon)"].join ,
                                    ['ipHostNumber','ipNetmaskNumber','ipNetworkNumber']
                                  )
       pub_ip = self.vpn_peer_ip(peer_dn)
       begin
       @vpndata.push({
                       :peer     => fqdn,
                       :pub_ip   => pub_ip,
                       :vpn_ip   => self.vpn_private_ipaddress(peer_dn),
                       :network  => rwarriors.fetch('ipHostNumber')[0],
                       :netmask  => rwarriors.fetch('ipNetmaskNumber')[0],
                       :cidr     => rwarriors.fetch('ipNetworkNumber')[0],
                       :pool     => NetAddr::CIDR.create(rwarriors.fetch('ipNetworkNumber')[0]).size,
                   })
       rescue IndexError
           warn 'Item with missing or invalid data ignored'
       end
     end
     return @vpndata 
  end
end
