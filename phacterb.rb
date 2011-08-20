#!/usr/bin/ruby
################################################################################
# ecternal facts we can use to populate erbs
################################################################################

class Phacterb
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
          return @fqdn
      end
      @fqdn = Socket.gethostname
      return @fqdn
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
      self_basedn.sub!(/\./, ',dc=')
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
        warn [ "unsuported record type: ", type ].join('')
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
                  ifcfg.push({ iface[:name] => iface.clone })
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
          ifcfg.push({ iface[:name] => iface.clone })
        end
      end
      return ifcfg
    end
  end

################################################################################
# "tests"                                                                      #

require 'pp' 
p = Phacterb.new
domain = p.domainname
data ={
        :fqdn     => p.fqdn,
        :hostname => p.hostname,
        :domain   => domain,
        :basedn   => p.basedn,
        :binddn   => p.binddn,
        :bindpw   => p.bindpw,
        :secret   => p.secret,
        :dns      => {
                        :soa   => p.dig(domain, 'SOA' ),
                        :ldaps => p.dig(['_ldaps._tcp',domain].join('.'),'SRV' ),
                        :mx    => p.dig(domain, 'MX' ),
                        :a     => p.dig(domain, 'A' ),
                        :ptr   => [],
                     },
}

data.fetch(:dns).fetch(:a).each do | a |
  ptrs = p.dig(a,'PTR' )
  ptrs.each do |ptr|
    data.fetch(:dns).fetch(:ptr).push(ptr)
  end
end

require 'yaml'
puts YAML::dump( data )
puts YAML::dump( p.lsearch(p.basedn,"(uid=whitejs)",['cn','uid','userPassword']) )
puts YAML::dump( p.lsearch( ["ou=VPNs,ou=Sets,",p.basedn].join, ["(cn=",domain,")"].join ,['uniqueMember']) )
puts YAML::dump( p.ifconfig )

#                                                                              #
################################################################################

end
