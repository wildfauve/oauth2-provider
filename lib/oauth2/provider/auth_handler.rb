module OAuth2

  class Provider

    class AuthHandler

      def initialize(request_value)
        @request_value = request_value
        @handler = if params[GRANT_TYPE]
          error ||= Provider::Error.new('must be a POST request') unless request.post?
          Provider::Exchange.new(resource_owner, params, error)
        else
          Provider::Authorization.new(resource_owner, params, error)
        end
      end

      def call
        @handler.()
      end

      def configuration
        @handler
      end

      private

      def params
        @request_value.params
      end

      def error
        @request_value.error
      end

      def resource_owner
        @request_value.resource_owner
      end

      def request
        @request_value.request
      end

    end  # class

  end  # provider

end  # oauth2
