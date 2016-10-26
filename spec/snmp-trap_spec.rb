require File.join(File.dirname(__FILE__), "helpers")
require "sensu/extensions/snmp-trap"

describe "Sensu::Extension::SNMPTrap" do
  include Helpers

  before do
    @extension = Sensu::Extension::SNMPTrap.new
    @extension.settings = {}
    @extension.logger = Sensu::Logger.get
  end

  it "can run" do
    async_wrapper do
      @extension.safe_run(event_template) do |output, status|
        puts output.inspect
        expect(status).to eq(0)
        async_done
      end
    end
  end
end
