require "sensu/extension"

module Sensu
  module Extension
    class SNMPTrap < Check
      def name
        "snmp_trap"
      end

      def description
        "receives snmp traps and translates them to check results"
      end

      def run(event)
        yield "it's a trap!", 0
      end
    end
  end
end
