require "sensu/extension"
require "sensu/extensions/snmp-trap/snmp-patch"
require "thread"

module Sensu
  module Extension
    class SNMPTrap < Check

      RESULT_MAP = [
        [/checkname/i, "name"],
        [/notification/i, "output"],
        [/description/i, "output"],
        [/pansystemseverity/i, Proc.new { |value| value > 3 ? 2 : 0 }, "status"],
        [/severity/i, "status"]
      ]

      RESULT_STATUS_MAP = [
        [/down/i, 2],
        [/authenticationfailure/i, 1]
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
          :imported_dir => File.join(Dir.tmpdir, "sensu_snmp_imported_mibs"),
          :result_attributes => {},
          :mappings => {
            :result => [],
            :result_status => []
          }
        }
        @options.merge!(@settings[:snmp_trap]) if @settings[:snmp_trap].is_a?(Hash)
        @options
      end

      def result_map
        return @result_map if @result_map
        if options[:mappings] &&
            options[:mappings].is_a?(Hash) &&
            options[:mappings][:result] &&
            options[:mappings][:result].is_a?(Array)
          @result_map = options[:mappings][:result] + RESULT_MAP
        else
          @result_map = RESULT_MAP
        end
      end

      def result_status_map
        return @result_status_map if @result_status_map
        if options[:mappings] &&
            options[:mappings].is_a?(Hash) &&
            options[:mappings][:result_status] &&
            options[:mappings][:result_status].is_a?(Array)
          @result_status_map = options[:mappings][:result_status] + RESULT_STATUS_MAP
        else
          @result_status_map = RESULT_STATUS_MAP
        end
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
        if @mibs_map[module_name]
          imports = @mibs_map[module_name][:imports]
          # two enumerators are required for preload ordering
          imports.each do |import|
            if @mibs_map[import]
              preload << @mibs_map[import][:mib_file]
            end
          end
          imports.each do |import|
            preload << determine_mib_preload(import)
          end
        else
          @logger.warn("snmp trap check extension unknown mib preload module", :module_name => module_name)
        end
        preload.flatten
      end

      def create_mibs_map!
        @logger.info("snmp trap check extension creating mibs map", :mibs_dir => options[:mibs_dir])
        @mibs_map = {}
        Dir.glob(File.join(options[:mibs_dir], "*")).each do |mib_file|
          begin
            mib_contents = IO.read(mib_file).force_encoding("UTF-8")
            module_name = mib_contents.scan(/([\w-]+)\s+DEFINITIONS\s+::=\s+BEGIN/).flatten.first
            details = {
              :mib_file => mib_file,
              :imports => mib_contents.scan(/FROM\s+([\w-]+)/).flatten
            }
            if @mibs_map.has_key?(module_name)
              @logger.warn("snmp trap check extension overriding mib map entry", {
                :module_name => module_name,
                :old_details => @mibs_map[module_name],
                :new_details => details
              })
            end
            @mibs_map[module_name] = details
          rescue => error
            @logger.error("snmp trap check extension mibs map error", {
              :mib_file => mib_file,
              :error => error.to_s
            })
          end
        end
        @mibs_map.each_key do |module_name|
          @mibs_map[module_name][:preload] = determine_mib_preload(module_name)
        end
        @mibs_map
      end

      def import_mibs!
        @logger.info("snmp trap check extension importing mibs", :mibs_dir => options[:mibs_dir])
        @mibs_map.each do |module_name, details|
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
      end

      def load_mibs!
        @logger.info("snmp trap check extension loading mibs", :imported_dir => options[:imported_dir])
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

      def determine_trap_name(trap)
        oid_symbolic_name = determine_trap_oid(trap)
        if oid_symbolic_name =~ /link(down|up)/i
          name = "link_status"
          trap.varbind_list.each do |varbind|
            symbolic_name = @mibs.name(varbind.name.to_oid)
            if symbolic_name =~ /ifindex/i || symbolic_name =~ /systemobject/i
              type_conversion = RUBY_ASN1_MAP[varbind.value.asn1_type]
              if type_conversion
                value = varbind.value.send(type_conversion)
                unless value == ""
                  name = "#{name}_#{value}"
                end
              end
            end
          end
          name
        else
          oid_symbolic_name
        end
      end

      def determine_trap_output(trap)
        oid_symbolic_name = determine_trap_oid(trap)
        if matched = /link(down|up)/i.match(oid_symbolic_name)
          link_status = matched[1].downcase
          output = "link is #{link_status}"
          trap.varbind_list.each do |varbind|
            symbolic_name = @mibs.name(varbind.name.to_oid)
            if symbolic_name =~ /ifalias/i || symbolic_name =~ /ifdesc/i
              type_conversion = RUBY_ASN1_MAP[varbind.value.asn1_type]
              if type_conversion
                value = varbind.value.send(type_conversion)
                unless value == ""
                  output = "#{output} (#{value})"
                end
              end
            end
          end
          output
        else
          "received snmp trap"
        end
      end

      def determine_trap_status(trap)
        oid_symbolic_name = determine_trap_oid(trap)
        mapping = result_status_map.detect do |mapping|
          oid_symbolic_name =~ mapping.first
        end
        mapping ? mapping.last : 0
      end

      def process_trap(trap)
        @logger.debug("snmp trap check extension processing a v2 trap")
        result = options[:result_attributes].merge(
          {
            "source" => determine_hostname(trap.source_ip),
            "handlers" => options[:handlers],
            "snmp_trap" => {}
          }
        )
        trap.varbind_list.each do |varbind|
          symbolic_name = @mibs.name(varbind.name.to_oid)
          type_conversion = RUBY_ASN1_MAP[varbind.value.asn1_type]
          if type_conversion
            value = varbind.value.send(type_conversion)
            result["snmp_trap"][symbolic_name] = value
            mapping = result_map.detect do |mapping|
              symbolic_name =~ mapping.first
            end
            if mapping && !result[mapping.last]
              if mapping.size == 3
                result[mapping.last] = mapping[1].call(value)
              else
                result[mapping.last] = value
              end
            end
          else
            @logger.error("snmp trap check extension failed to convert varbind", {
              :symbolic_name => symbolic_name,
              :asn1_type => varbind.value.asn1_type,
              :raw_value => varbind.value
            })
          end
        end
        result["name"] ||= determine_trap_name(trap)
        result["output"] ||= determine_trap_output(trap)
        result["status"] ||= determine_trap_status(trap)
        send_result(result)
      end

      def start_trap_processor!
        @processor = Thread.new do
          create_mibs_map!
          import_mibs!
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
