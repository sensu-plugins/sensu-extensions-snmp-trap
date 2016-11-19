require "sensu/extension"
require "sensu/extensions/snmp-trap/snmp-patch"
require "thread"

module Sensu
  module Extension
    class SNMPTrap < Check

      RESULT_MAP = [
        [/checkname/i, :name],
        [/notification/i, :output],
        [/severity/i, :status]
      ]

      RUBY_ASN1_MAP = {
        "INTEGER" => :to_i,
        "OCTET STRING" => :to_s,
        "OBJECT IDENTIFIER" => :to_s,
        "IpAddress" => :to_s,
        "Counter32" => :to_i,
        "Gauge32" => :to_i,
        "Unsigned32" => :to_i,
        "TimeTicks" => :to_i,
        "Opaque" => :to_s,
        "Counter64" => :to_i
      }

      def name
        "snmp_trap"
      end

      def description
        "receives snmp traps and translates them to check results"
      end

      def definition
        {
          name: name,
          publish: false
        }
      end

      def options
        return @options if @options
        @options = {
          :bind => "0.0.0.0",
          :port => 1062,
          :community => "public",
          :handlers => ["default"],
          :mibs_dir => "/etc/sensu/mibs",
          :imported_dir => File.join(Dir.tmpdir, "sensu_snmp_imported_mibs")
        }
        @options.merge!(@settings[:snmp_trap]) if @settings[:snmp_trap].is_a?(Hash)
        @options
      end

      def start_snmpv2_listener!
        @listener = SNMP::TrapListener.new(
          :host => options[:bind],
          :port => options[:port],
          :community => options[:community]) do |listener|
          listener.on_trap_v2c do |trap|
            @logger.debug("snmp trap check extension received a v2 trap")
            @traps << trap
          end
        end
      end

      def determine_mib_preload(module_name)
        preload = []
        if @mib_map[module_name]
          @mib_map[module_name][:imports].each do |import|
            if @mib_map[import]
              preload << @mib_map[import][:mib_file]
            end
            preload << determine_mib_preload(import)
          end
        else
          @logger.fatal("snmp trap check extension unknown mib preload", :module_name => module_name)
        end
        preload.flatten
      end

      def create_mib_map!
        @logger.debug("snmp trap check extension creating mib map", :mibs_dir => options[:mibs_dir])
        @mib_map = {}
        Dir.glob(File.join(options[:mibs_dir], "*")).each do |mib_file|
          mib_contents = IO.read(mib_file)
          module_name = mib_contents.scan(/([\w-]+)\s+DEFINITIONS\s+::=\s+BEGIN/).flatten.first
          details = {
            :mib_file => mib_file,
            :imports => mib_contents.scan(/FROM\s+([\w-]+)/).flatten
          }
          if @mib_map.has_key?(module_name)
            @logger.debug("snmp trap check extension overriding mib map entry", {
              :module_name => module_name,
              :details => details
            })
          end
          @mib_map[module_name] = details
        end
        @mib_map.each_key do |module_name|
          @mib_map[module_name][:preload] = determine_mib_preload(module_name)
        end
        puts @mib_map
        @mib_map
      end

      def load_mibs!
        @logger.debug("snmp trap check extension importing mibs", {
          :mibs_dir => options[:mibs_dir],
          :imported_dir => options[:imported_dir]
        })
        @mib_map.each do |module_name, details|
          @logger.debug("snmp trap check extension importing mib", {
            :module_name => module_name,
            :details => details
          })
          begin
            @logger.debug("snmp trap check extension mib dependencies", {
              :module_name => module_name,
              :details => details
            })
            unless details[:preload].empty?
              arguments = "-p "
              arguments << details[:preload].map { |preload| preload }.join(" -p ")
            else
              arguments = nil
            end
            SNMP::MIB.import_module(details[:mib_file], options[:imported_dir], arguments)
          rescue StandardError, SyntaxError => error
            @logger.debug("snmp trap check extension failed to import mib", {
              :module_name => module_name,
              :details => details,
              :error => error
            })
          end
        end
        @mibs = SNMP::MIB.new
        @logger.debug("snmp trap check extension loading mibs")
        SNMP::MIB.list_imported(/.*/, SNMP::MIB::DEFAULT_MIB_PATH).each do |module_name|
          @logger.debug("snmp trap check extension loading mib", :module_name => module_name)
          @mibs.load_module(module_name, SNMP::MIB::DEFAULT_MIB_PATH)
        end
        SNMP::MIB.list_imported(/.*/, options[:imported_dir]).each do |module_name|
          @logger.debug("snmp trap check extension loading mib", :module_name => module_name)
          @mibs.load_module(module_name, options[:imported_dir])
        end
        @mibs
      end

      def send_result(result)
        socket = UDPSocket.new
        socket.send(Sensu::JSON.dump(result), 0, "127.0.0.1", 3030)
        socket.close
      end

      def determine_hostname(address)
        begin
          Resolv.getname(address)
        rescue Resolv::ResolvError
          @logger.debug("snmp trap check extension unable to resolve hostname", :address => address)
          address
        end
      end

      def determine_trap_oid(trap)
        varbind = trap.varbind_list.detect do |varbind|
          varbind.name.to_oid == SNMP::SNMP_TRAP_OID_OID
        end
        begin
          @mibs.name(varbind.value.to_oid).gsub(/[^\w\.-]/i, "-")
        rescue
          varbind.value.to_s.gsub(/[^\w\.-]/i, "-") rescue "trap_oid_unknown"
        end
      end

      def trap_varbind_list(trap)
        trap.varbind_list.map { |varbind|
          begin
            symbolic_name = @mibs.name(varbind.name.to_oid)
            "#{symbolic_name} -> #{varbind.value}"
          rescue
            "#{varbind.name} -> #{varbind.value}"
          end
        }.join(" | ")
      end

      def process_trap(trap)
        @logger.debug("snmp trap check extension processing a v2 trap")
        result = {
          :source => determine_hostname(trap.source_ip),
          :handlers => options[:handlers]
        }
        trap.varbind_list.each do |varbind|
          symbolic_name = @mibs.name(varbind.name.to_oid)
          mapping = RESULT_MAP.detect do |mapping|
            symbolic_name =~ mapping.first
          end
          if mapping && !result[mapping.last]
            type_conversion = RUBY_ASN1_MAP[varbind.value.asn1_type]
            if type_conversion
              result[mapping.last] = varbind.value.send(type_conversion)
            end
          end
        end
        result[:name] ||= determine_trap_oid(trap)
        result[:output] ||= trap_varbind_list(trap)
        result[:status] ||= 3
        send_result(result)
      end

      def start_trap_processor!
        @processor = Thread.new do
          create_mib_map!
          load_mibs!
          loop do
            process_trap(@traps.pop)
          end
        end
        @processor.abort_on_exception = true
        @processor
      end

      def post_init
        @traps = Queue.new
        start_snmpv2_listener!
        start_trap_processor!
      end

      def stop
        @listener.kill if @listener
        @processor.kill if @processor
      end

      def run(event, &callback)
        yield "no-op", 0
      end
    end
  end
end
