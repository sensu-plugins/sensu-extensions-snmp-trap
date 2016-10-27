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
      SNMP::VarBind.new("1.3.6.1.4.1.45717.1.1.1.2", SNMP::OctetString.new("alert")),
      SNMP::VarBind.new("1.3.6.1.4.1.45717.1.1.1.4", SNMP::OctetString.new("test")),
      SNMP::VarBind.new("1.3.6.1.4.1.45717.1.1.1.5", SNMP::Integer32.new(2))
    ]
    SNMP::SNMPv2_Trap.new(1, SNMP::VarBindList.new(varbind_list))
  end

  let(:snmpv2_message) do
    SNMP::Message.new(:SNMPv2c, "public", snmpv2_pdu).encode
  end

  it "can run" do
    async_wrapper do
      EM::open_datagram_socket("127.0.0.1", 3030, Helpers::TestServer) do |server|
        server.expected = '{"source": "localhost", "name": "test", "output": "alert", "status": 2, "handlers": ["default"]}'
      end
      EM.next_tick do
        EM::open_datagram_socket("0.0.0.0", 0, nil) do |socket|
          socket.send_datagram(snmpv2_message, "127.0.0.1", 1062)
          socket.close_connection_after_writing
        end
      end
    end
  end
end
