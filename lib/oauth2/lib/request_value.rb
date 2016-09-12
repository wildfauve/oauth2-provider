module OAuth2

  module Lib

    class RequestValue

      attr_reader :resource_owner, :params, :error, :request

      def initialize(resource_owner:, params:, error:, request:)
        @resource_owner = resource_owner
        @params = params
        @error = error
        @request = request
      end

    end

  end

end
