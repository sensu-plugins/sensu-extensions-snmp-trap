require File.join(File.dirname(__FILE__), "helpers")
require "sensu/extensions/snmp-trap"
require "socket"

describe "Sensu::Extension::SNMPTrap" do
  include Helpers

  before do
    @extension = Sensu::Extension::SNMPTrap.new
    @extension.settings = {
      :snmp_trap => {
        :mibs_dir => File.join(File.dirname(__FILE__), "mibs")
      }
    }
    @extension.logger = Sensu::Logger.get
  end

  let(:snmpv2_pdu) do
    varbind_list = [
      SNMP::VarBind.new(SNMP::SYS_UP_TIME_OID, SNMP::TimeTicks.new(20)),
      SNMP::VarBind.new(SNMP::SNMP_TRAP_OID_OID, SNMP::ObjectId.new("1.3.6.1.4.1.45717.1.0")),
      SNMP::VarBind.new("1.3.6.1.4.1.45717.1.1.1.2", SNMP::OctetString.new("alert"))
    ]
    SNMP::SNMPv2_Trap.new(1, SNMP::VarBindList.new(varbind_list))
  end

  let(:snmpv2_message) do
    SNMP::Message.new(:SNMPv2c, "public", snmpv2_pdu).encode
  end

  it "can run" do
    async_wrapper do
      EM::Timer.new(0.5) do
        socket = UDPSocket.new
        socket.send(snmpv2_message, 0, "127.0.0.1", 1062)
        socket.close
        @extension.safe_run(event_template) do |output, status|
          expect(output).to eq("alert")
          expect(status).to eq(0)
          async_done
        end
      end
    end
  end
end
