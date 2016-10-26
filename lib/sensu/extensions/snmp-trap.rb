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

      def options
        return @options if @options
        @options = {
          :bind => "0.0.0.0",
          :port => 1062,
          :community => "public",
          :handler => "default",
          :mibs_dir => "/etc/sensu/mibs"
        }
        @options.merge!(@settings[:snmp]) if @settings[:snmp].is_a?(Hash)
        @options
      end

      def start_listener
        @listener = ::SNMP::TrapListener.new(:host => options[:bind], :port => options[:port]) do |listener|
          listener.on_trap_v2c do |trap|
            @logger.debug("snmp trap check extension received a v2 trap")
            @traps << trap
          end
        end
      end

      def post_init
        @traps = Queue.new
        start_listener
      end

      def run(event, &callback)
        wait_for_trap = Proc.new do
          [@traps.pop, 0]
        end
        EM.next_tick do
          EM.defer(wait_for_trap, callback)
        end
      end
    end
  end
end
