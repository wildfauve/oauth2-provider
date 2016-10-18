module OAuth2
  class Provider

    class Exchange
      attr_reader :client, :error, :error_description

      REQUIRED_PARAMS = [CLIENT_ID, CLIENT_SECRET, GRANT_TYPE]

      NATIVE_APP_REQUIRED_PARAMS = [GRANT_TYPE, CODE_VERIFIER]

      NATIVE_APP_NOT_ALLOWED = [CLIENT_SECRET]

      VALID_GRANT_TYPES = [AUTHORIZATION_CODE, PASSWORD, ASSERTION, REFRESH_TOKEN, CLIENT_CREDENTIALS]

      REQUIRED_PASSWORD_PARAMS = [USERNAME, PASSWORD]
      REQUIRED_ASSERTION_PARAMS = [ASSERTION_TYPE, ASSERTION]

      RESPONSE_HEADERS = {
        'Cache-Control' => 'no-store',
        'Content-Type'  => 'application/json'
      }

      def initialize(resource_owner, params, transport_error = nil)
        @params     = params
        @scope      = params[SCOPE]
        @grant_type = @params[GRANT_TYPE]

        @transport_error = transport_error

        validate!
      end

      # To keep the 2 handlers (this and Authorization) consistent, the call returns itself
      # as the caller drives the coordination here.
      def call
        self
      end

      # This service generates both access tokens and OpenId Connect JWTs.
      # This would replace the ID Service JWT token generation (and the Oauth::Token model)
      # It is not integrated into ID as yet
      def generate_id_token
        return if not valid? or @already_updated
        @authorization.exchange_for_token!(token_type: :jwt)
        @already_updated = true
      end

      def redirect?
        false
      end

      def response_body
        return jsonize(ERROR, ERROR_DESCRIPTION) unless valid?
        update_authorization

        response = {}
        [ACCESS_TOKEN, REFRESH_TOKEN, SCOPE].each do |key|
        #[ACCESS_TOKEN, REFRESH_TOKEN, SCOPE, ID_TOKEN].each do |key|
          value = @authorization.__send__(key)
          response[key] = value if value
        end
        if expiry = @authorization.expires_in
          response[EXPIRES_IN] = expiry
        end

        JSON.unparse(response)
      end

      def response_headers
        RESPONSE_HEADERS
      end

      def response_status
        valid? ? 200 : 400
      end

      def scopes
        scopes = @scope ? @scope.split(/\s+/).delete_if { |s| s.empty? } : []
        Set.new(scopes)
      end

      def update_authorization
        return if not valid? or @already_updated
        @authorization.exchange!
        @already_updated = true
      end

      def valid?
        @error.nil?
      end

      def relying_party
        # native apps may not provide a client_id, so we need to
        # use the authorization_code to index into the client
        @client ||= if @params[CLIENT_ID]
          Model::Client.find_by_client_id(@params[CLIENT_ID])
        else
          Model::Authorization.find_by_code(@params[CODE]).try(:client)
        end
      end

      def owner
        @authorization && @authorization.owner
      end


    private

      def jsonize(*ivars)
        hash = {}
        ivars.each { |key| hash[key] = instance_variable_get("@#{key}") }
        JSON.unparse(hash)
      end

      def validate!

        [ :check_transport_error,
          :determine_relying_party_intent,
          :validate_required_params,
          :validate_native_app_security_leak,
          :validate_client,
          :validate_grant_types,
          :validate_grant,
          :validate_scope
        ].each do |validation|
          __send__(validation)
          break if @error
        end
      end

      def check_transport_error
        if @transport_error
          @error = @transport_error.error
          @error_description = @transport_error.error_description
          return
        end
      end


      def determine_relying_party_intent
        if access_by_code
          unless relying_party
            @error = INVALID_CLIENT
            @error_description = "Client can not be found for code #{@params[CODE]}"
          end
        end
      end

      def validate_grant_types
        unless VALID_GRANT_TYPES.include?(@grant_type)
          @error = UNSUPPORTED_GRANT_TYPE
          @error_description = "The grant type #{@grant_type} is not recognized"
        end
      end

      def validate_grant
        __send__("validate_#{@grant_type}")
      end

      def access_by_code
        !@params[CLIENT_ID] && @params[CODE]
      end

      def validate_required_params
        # Native apps may not provide client_id/secret, so, dont check for them
        checked_params = relying_party.try(:native_app?) ? NATIVE_APP_REQUIRED_PARAMS : REQUIRED_PARAMS
        checked_params.each do |param|
          next if @params.has_key?(param)
          @error = INVALID_REQUEST
          @error_description = "Missing required parameter #{param}"
        end
      end

      def validate_native_app_security_leak
        if relying_party.try(:native_app?)
          not_allowed = NATIVE_APP_NOT_ALLOWED & @params.keys
          unless not_allowed.empty?
            @error = INVALID_REQUEST
            @error_description = "#{not_allowed.map(&:to_sym)} must not be provided for native app"
          end
        end
      end

      def validate_client
        unless relying_party
          @error = INVALID_CLIENT
          @error_description = "Unknown client ID #{@params[CLIENT_ID]}"
        end

        if relying_party and not relying_party.valid_client_secret?(@params[CLIENT_SECRET])
          @error = INVALID_CLIENT
          @error_description = 'Parameter client_secret does not match'
        end
      end

      def validate_client_credentials
        owner = relying_party.owner
        @authorization = Provider.handle_client_credential(relying_party, owner, scopes)
        return validate_authorization if @authorization

        @error = INVALID_GRANT
        @error_description = 'The access grant you supplied is invalid'
      end

      def validate_scope
        if @authorization and not @authorization.in_scope?(scopes)
          @error = INVALID_SCOPE
          @error_description = 'The request scope was never granted by the user'
        end
      end

      def validate_authorization_code
        unless @params[CODE]
          @error = INVALID_REQUEST
          @error_description = "Missing required parameter code"
        end

        if relying_party.redirect_uri and relying_party.redirect_uri != @params[REDIRECT_URI]
          @error = REDIRECT_MISMATCH
          @error_description = "Parameter redirect_uri does not match registered URI"
        end

        unless @params.has_key?(REDIRECT_URI)
          @error = INVALID_REQUEST
          @error_description = "Missing required parameter redirect_uri"
        end

        return if @error

        @authorization = relying_party.authorizations.find_by_code(@params[CODE])
        validate_authorization
      end

      def validate_password
        REQUIRED_PASSWORD_PARAMS.each do |param|
          next if @params.has_key?(param)
          @error = INVALID_REQUEST
          @error_description = "Missing required parameter #{param}"
        end

        return if @error

        @authorization = Provider.handle_password(relying_party, @params[USERNAME], @params[PASSWORD], scopes)
        return validate_authorization if @authorization

        @error = INVALID_GRANT
        @error_description = 'The access grant you supplied is invalid'
      end

      def validate_assertion
        REQUIRED_ASSERTION_PARAMS.each do |param|
          next if @params.has_key?(param)
          @error = INVALID_REQUEST
          @error_description = "Missing required parameter #{param}"
        end

        if @params[ASSERTION_TYPE]
          uri = URI.parse(@params[ASSERTION_TYPE]) rescue nil
          unless uri and uri.absolute?
            @error = INVALID_REQUEST
            @error_description = 'Parameter assertion_type must be an absolute URI'
          end
        end

        return if @error

        assertion = Assertion.new(@params)
        @authorization = Provider.handle_assertion(relying_party, assertion, scopes)
        return validate_authorization if @authorization

        @error = UNAUTHORIZED_CLIENT
        @error_description = 'Client cannot use the given assertion type'
      end

      def validate_refresh_token
        refresh_token_hash = Lib::SecureCodeScheme.hashify(@params[REFRESH_TOKEN])
        @authorization = relying_party.authorizations.find_by_refresh_token_hash(refresh_token_hash)
        validate_authorization
      end

      def validate_authorization
        unless @authorization
          @error = INVALID_GRANT
          @error_description = 'The access grant you supplied is invalid'
        end

        if @authorization and @authorization.expired?
          @error = INVALID_GRANT
          @error_description = 'The access grant you supplied is invalid'
        end

        # The code is actually a PKCE code when from a native apps
        # we need to validate using the code_verifier
        if relying_party.native_app?

          secure_scheme = Lib::SecureCodeScheme

          code, method = secure_scheme.pkce_decode_code_and_method(@params[CODE])

          if code.nil?
            @error = INVALID_GRANT
            @error_description = 'Code is invalid'
          end
          return if @error

          ver = secure_scheme.pkce_run_hash_on_verifier(@params[CODE_VERIFIER], method)

          unless code == ver
            @error = INVALID_GRANT
            @error_description = 'Code verifier does not agree with code challenge'
          end

        end

      end
    end

    class Assertion
      attr_reader :type, :value
      def initialize(params)
        @type  = params[ASSERTION_TYPE]
        @value = params[ASSERTION]
      end
    end

  end
end
