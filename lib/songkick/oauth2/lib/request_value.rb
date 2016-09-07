module Songkick

  module OAuth2

    module Lib

      class RequestValue

        attr_reader :resource_owner, :params, :error

        def initialize(resource_owner:, params:, error: )
          @resource_owner = resource_owner
          @params = params
          @error = error
        end


      end

    end

  end

end
