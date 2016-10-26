require File.join(File.dirname(__FILE__), "helpers")
require "sensu/extensions/snmp-trap"

describe "Sensu::Extension::SNMPTrap" do
  include Helpers

  before do
    @extension = Sensu::Extension::SNMPTrap.new
  end

  it "can run" do
    @extension.safe_run(event_template) do |output, status|
      expect(output).to eq("it's a trap!")
      expect(status).to eq(0)
    end
  end
end
