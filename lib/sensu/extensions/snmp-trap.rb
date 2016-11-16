require "sensu/extension"
require "thread"
require "snmp"

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
          :mibs_dir => "/etc/sensu/mibs"
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

      def load_mibs!
        @logger.debug("snmp trap check extension importing mibs", :mibs_dir => options[:mibs_dir])
        begin
          Dir.glob(File.join(options[:mibs_dir], "*")) do |mib_file|
            @logger.debug("snmp trap check extension importing mib", :mib_file => mib_file)
            SNMP::MIB.import_module(mib_file)
          end
        rescue StandardError, SyntaxError => error
          @logger.debug("snmp trap check extension failed to import mib", {
            :mib_file => mib_file,
            :error => error
          })
        end
        @mibs = SNMP::MIB.new
        @logger.debug("snmp trap check extension loading mibs")
        SNMP::MIB.list_imported.each do |module_name|
          @logger.debug("snmp trap check extension loading mib", :module_name => module_name)
          @mibs.load_module(module_name)
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
        varbind.value.to_s.gsub(/[^\w\.-]/i, "-") rescue "trap_oid_unknown"
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
        result[:output] ||= trap.inspect
        result[:status] ||= 3
        send_result(result)
      end

      def start_trap_processor!
        @processor = Thread.new do
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
