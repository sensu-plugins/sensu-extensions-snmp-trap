require "snmp"

module SNMP
  class MIB
    def warn(message)
      @sensu_logger ||= Sensu::Logger.get
      @sensu_logger.warn("snmp trap check extension mib warning", :warning => message.downcase)
    end

    class << self
      def warn(message)
        @sensu_logger ||= Sensu::Logger.get
        @sensu_logger.warn("snmp trap check extension mib warning", :warning => message.downcase)
      end

      def import_module(module_file, mib_dir=DEFAULT_MIB_PATH, raw_arguments=nil)
        raise "smidump tool must be installed" unless import_supported?
        FileUtils.makedirs mib_dir
        # PATCH: add arguments support
        arguments = raw_arguments ? " #{raw_arguments}" : ""
        # PATCH: redirect STDERR to /dev/null
        mib_hash = `smidump#{arguments} -k -f python #{module_file} 2>/dev/null`
        mib = eval_mib_data(mib_hash)
        if mib
          module_name = mib["moduleName"]
          raise "#{module_file}: invalid file format; no module name" unless module_name
          if mib["nodes"]
            oid_hash = {}
            mib["nodes"].each { |key, value| oid_hash[key] = value["oid"] }
            if mib["notifications"]
              mib["notifications"].each { |key, value| oid_hash[key] = value["oid"] }
            end
            File.open(module_file_name(module_name, mib_dir), 'w') do |file|
              YAML.dump(oid_hash, file)
              file.puts
            end
            module_name
          else
            # PATCH: downcase and removed ***
            warn "no nodes defined in: #{module_file}"
            nil
          end
        else
          # PATCH: downcase and removed ***
          warn "import failed for: #{module_file}"
          nil
        end
      end
    end
  end
end
