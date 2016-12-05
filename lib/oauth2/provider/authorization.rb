module OAuth2
  class Provider

    class Authorization
      attr_reader :owner, :client,
                  :code, :access_token,
                  :expires_in, :refresh_token,
                  :error, :error_description

      REQUIRED_PARAMS = [RESPONSE_TYPE, CLIENT_ID, REDIRECT_URI]

      ADDITIONAL_NATIVE_PARAMS = [CODE_CHALLENGE, CODE_CHALLENGE_METHOD]

      NATIVE_APP_REQUIRED_PARAMS = REQUIRED_PARAMS + ADDITIONAL_NATIVE_PARAMS

      VALID_PARAMS    = REQUIRED_PARAMS + [SCOPE, STATE, LOGIN_HINT]
      VALID_NATIVE_PARAMS = VALID_PARAMS +  ADDITIONAL_NATIVE_PARAMS

      VALID_RESPONSES = [CODE, TOKEN, CODE_AND_TOKEN]

      def initialize(resource_owner, params, transport_error = nil)
        @owner  = resource_owner
        @params = params
        @scope  = params[SCOPE]
        @state  = params[STATE]

        @transport_error = transport_error

        validate!

      end

      def call
        return self unless @owner and not @error

        return self unless resource_owner_model and resource_owner_model.in_scope?(scopes) and not resource_owner_model.expired?

        @authorized = true

        if @params[RESPONSE_TYPE] =~ /code/
          @code = resource_owner_model.generate_code(additional_attributes: @params, predicate: code_predicate_function)
        end

        if @params[RESPONSE_TYPE] =~ /token/
          @access_token = resource_owner_model.generate_access_token
        end

        self

      end

      def scopes
        scopes = @scope ? @scope.split(/\s+/).delete_if { |s| s.empty? } : []
        Set.new(scopes)
      end

      def unauthorized_scopes
        resource_owner_model ? scopes.select { |s| not resource_owner_model.in_scope?(s) } : scopes
      end

      def grant_access!(options = {})
        auth = Model::Authorization.for(@owner, relying_party, params.merge('duration' => options[:duration]))
          # :response_type => @params[RESPONSE_TYPE],
          # :scope         => @scope,
          # :duration      => options[:duration],
          # )

        @code          = auth.code
        @access_token  = auth.access_token
        @refresh_token = auth.refresh_token
        @expires_in    = auth.expires_in

        unless @params[RESPONSE_TYPE] == CODE
          @expires_in = auth.expires_in
        end

        @authorized = true
      end

      def deny_access!
        @code = @access_token = @refresh_token = nil
        @error = ACCESS_DENIED
        @error_description = "The user denied you access"
      end

      def params
        params = {}
        valid_params.each { |key| params[key] = @params[key] if @params.has_key?(key) }
        params
      end

      def redirect?
        relying_party && (@authorized || !valid? || redirectable_error?)
      end

      def redirect_uri
        return nil unless relying_party
        base_redirect_uri = relying_party.redirect_uri
        q = (base_redirect_uri =~ /\?/) ? '&' : '?'

        if not valid?
          query = to_query_string(ERROR, ERROR_DESCRIPTION, STATE)
          "#{ base_redirect_uri }#{ q }#{ query }"

        elsif @params[RESPONSE_TYPE] == CODE_AND_TOKEN
          query    = to_query_string(CODE, STATE)
          fragment = to_query_string(ACCESS_TOKEN, EXPIRES_IN, SCOPE)
          "#{ base_redirect_uri }#{ query.empty? ? '' : q + query }##{ fragment }"

        elsif @params[RESPONSE_TYPE] == TOKEN
          fragment = to_query_string(ACCESS_TOKEN, EXPIRES_IN, SCOPE, STATE)
          "#{ base_redirect_uri }##{ fragment }"

        else
          query = to_query_string(CODE, SCOPE, STATE)
          "#{ base_redirect_uri }#{ q }#{ query }"
        end
      end

      def response_body
        warn "OAuth2::Provider::Authorization no longer returns a response body "+
             "when the request is invalid. You should call valid? to determine "+
             "whether to render your login page or an error page."
        nil
      end

      def response_headers
        redirect? ? {} : {'Cache-Control' => 'no-store'}
      end

      def response_status
        return 302 if redirect?
        return 200 if valid?
        relying_party ? 302 : 400
      end

      def valid?
        @error.nil?
      end

      def code_predicate_function
        if native_app_client?
          ->(code) {true}
        else
          ->(code) {Model::Helpers.count(relying_party.authorizations, :code => code).zero?}
        end
      end

      def relying_party
        unless @transport_error
          @client ||= @params[CLIENT_ID] && Model::Client.find_by_client_id(@params[CLIENT_ID])
        end
      end

      def resource_owner_model
        unless @transport_error
          @model ||= @owner.oauth2_authorization_for(relying_party)
        end
      end

      def native_app_client?
        relying_party.try(:native_app?)
      end

      private

      # transport errors will not result in a redirect.
      # params-based errors will, however
      def redirectable_error?
        @error && !@transport_error
      end

      def validate!
        [ :check_transport_error,
          :check_params,
          :check_relying_party,
          :check_native_code_challenge,
          :check_native_code_challenge_method,
          :check_for_new_lines,
          :check_response_types,
          :check_redirect_uri].each do |validation|
            __send__(validation)
            break if @error
        end
      end

      def check_transport_error
        if @transport_error
          @error = @transport_error.error
          @error_description = @transport_error.error_description
        end
      end

      def check_relying_party
        unless relying_party
          @error = INVALID_CLIENT
          @error_description = "Unknown client ID #{@params[CLIENT_ID]}"
        end
      end

      def check_params
        missing_params = checked_params - @params.keys
        if missing_params.any?
          @error = INVALID_REQUEST
          @error_description = "Missing required parameter(s) #{missing_params.map(&:to_sym)}"
        end

      end

      def check_native_code_challenge
        # Check that where is a code challege
        if relying_party.native_app?
          if @params[CODE_CHALLENGE].nil?
            @error = INVALID_REQUEST
            @error_description = "Code code_challenge must be provided"
          end
        end
      end


      def check_native_code_challenge_method
        # Check that where is a code_challenge_method is "S256" when PKCE is enabled (for native_apps)
        if relying_party.native_app?
          if @params[CODE_CHALLENGE_METHOD] != CODE_CHALLENGE_HASH_METHOD
            @error = INVALID_REQUEST
            @error_description = "Code code_challenge_method MUST be 'SHA256'"
          end
        end
      end

      def check_for_new_lines
        [SCOPE, STATE].each do |param|
          next unless @params.has_key?(param)
          if @params[param] =~ /\r\n/
            @error = INVALID_REQUEST
            @error_description = "Illegal value for #{param} parameter"
          end
        end
      end

      def check_response_types
        unless VALID_RESPONSES.include?(@params[RESPONSE_TYPE])
          @error = UNSUPPORTED_RESPONSE
          @error_description = "Response type #{@params[RESPONSE_TYPE]} is not supported"
        end
      end

      def check_redirect_uri
        if relying_party and relying_party.redirect_uri and relying_party.redirect_uri != @params[REDIRECT_URI]
          @error = REDIRECT_MISMATCH
          @error_description = "Parameter #{REDIRECT_URI} does not match registered URI"
        end
      end

      def checked_params
        native_app_client? ? NATIVE_APP_REQUIRED_PARAMS : REQUIRED_PARAMS
      end

      def valid_params
        native_app_client? ? VALID_NATIVE_PARAMS : VALID_PARAMS
      end

      def to_query_string(*ivars)
        ivars.map { |key|
          value = instance_variable_get("@#{key}")
          value = value.join(' ') if Array === value
          value ? "#{ key }=#{ CGI.escape(value.to_s) }" : nil
        }.compact.join('&')
      end
    end

  end
end
