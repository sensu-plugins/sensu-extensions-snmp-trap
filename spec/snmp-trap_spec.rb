require File.join(File.dirname(__FILE__), "helpers")
require "sensu/extensions/snmp-trap"

describe "Sensu::Extension::SNMPTrap" do
  include Helpers

  before do
    @extension = Sensu::Extension::SNMPTrap.new
    @extension.settings = {}
    @extension.logger = Sensu::Logger.get
  end

  let(:snmp_pdu) do
    pen = "1.3.6.1.4.1.45717" + ".1.1.1"
    varbind_list = [
      VarBind.new(pen + ".1", "113C8FF4-88C3-40A6-9DDE-17470635FED0")
    ]
    SNMPv2_Trap.new(1, VarBindList.new(varbind_list))
  end

  let(:snmpv2_message) do
    Message.new(:SNMPv2c, "public", snmp_pdu).encode
  end

  it "can run" do
    async_wrapper do
      @extension.safe_run(event_template) do |output, status|
        socket = UDPSocket.new
        socket.send(message, 0, "127.0.0.1", 162)
        socket.close
        puts output.inspect
        expect(status).to eq(0)
        async_done
      end
    end
  end
end
