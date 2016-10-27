require "sensu/extension"
require "thread"
require "snmp"

module Sensu
  module Extension
    class SNMPTrap < Check
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
          :handler => "default",
          :mibs_dir => "/etc/sensu/mibs"
        }
        @options.merge!(@settings[:snmp_trap]) if @settings[:snmp_trap].is_a?(Hash)
        @options
      end

      def start_snmpv2_listener!
        @listener = SNMP::TrapListener.new(:host => options[:bind], :port => options[:port]) do |listener|
          listener.on_trap_v2c do |trap|
            @logger.debug("snmp trap check extension received a v2 trap")
            @traps << trap
          end
        end
      end

      def load_mibs!
        @mibs = SNMP::MIB.new
        @logger.debug("snmp trap check extension importing mibs", :mibs_dir => options[:mibs_dir])
        Dir.glob(File.join(options[:mibs_dir], "*")) do |mib_file|
          module_name = SNMP::MIB.import_module(mib_file)
          if module_name
            @logger.debug("snmp trap check extension loading mib", :module_name => module_name)
            @mibs.load_module(module_name)
          end
        end
        @mibs
      end

      def process_trap(trap)
        @logger.debug("snmp trap check extension processing a v2 trap")
        @results << trap
      end

      def start_trap_processor!
        @processor = Thread.new do
          load_mibs!
          loop do
            process_trap(@traps.pop)
          end
        end
        @processor.abort_on_exception = true
      end

      def post_init
        @traps = Queue.new
        @results = Queue.new
        start_snmpv2_listener!
        start_trap_processor!
      end

      def stop
        @listener.kill if @listener
        @processor.kill if @processor
      end

      def run(event, &callback)
        wait_for_result = Proc.new do
          [@results.pop, 0]
        end
        EM.next_tick do
          EM.defer(wait_for_result, callback)
        end
      end
    end
  end
end
