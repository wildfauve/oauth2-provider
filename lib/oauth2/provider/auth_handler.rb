module OAuth2

  class Provider

    class AuthHandler

      def initialize(request_value)
        @handler = if request_value.params[GRANT_TYPE]
          Provider::Exchange.new(request_value.resource_owner, request_value.params, error_to_pass(request_value))
        else
          Provider::Authorization.new(request_value.resource_owner, request_value.params, request_value.error)
        end
      end

      def call
        @handler.()
      end

      def configuration
        @handler
      end

      private

      def error_to_pass(request_value)
        return request_value.error if request_value.error
        Provider::Error.new('must be a POST request') unless request_value.request.post?
      end

    end  # class

  end  # provider

end  # oauth2
