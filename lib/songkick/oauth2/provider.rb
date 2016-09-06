require 'base64'
require 'bcrypt'
require 'cgi'
require 'digest/sha1'
require 'json'
require 'logger'
require 'rack'

begin
  require 'securerandom'
rescue LoadError
end

module Songkick
  module OAuth2
    ROOT = File.expand_path(File.dirname(__FILE__) + '/..')
    TOKEN_SIZE = 160

    autoload :Model,  ROOT + '/oauth2/model'
    autoload :Router, ROOT + '/oauth2/router'
    autoload :Schema, ROOT + '/oauth2/schema'

    def self.random_string
      if defined? SecureRandom
        SecureRandom.hex(TOKEN_SIZE / 8).to_i(16).to_s(36)
      else
        rand(2 ** TOKEN_SIZE).to_s(36)
      end
    end

    def self.pkce_string(attributes)
      cipher = aes_cipher(:encrypt)
      Base64.urlsafe_encode64(cipher.update(pkce_tokenise(attributes[CODE_CHALLENGE.to_sym], attributes[CODE_CHALLENGE_METHOD.to_sym])) + cipher.final)
    end

    def self.pkce_decrypt(code)
      cipher = aes_cipher(:decrypt)
      cipher.update(Base64.urlsafe_decode64(code)) + cipher.final
    end

    def self.aes_cipher(direction)
      cipher = OpenSSL::Cipher::AES.new(256, :CBC)
      cipher.send(direction)
      cipher.key = "bff19d8c59f31f68d70e34abae5c93420c17f50bc3c278878593ced6b03d916d"
      cipher.iv = "aa8dbfb30de9bac490cab3aa551376add3462bb9080e0d534f8301cd094f56a7"
      cipher
    end

    def self.pkce_tokenise(challenge, method)
      "#{challenge}:#{method}"
    end

    def self.pkce_de_tokenise(string)

    end


    # Generates a SecureRandom string until the predicate is met
    # (i.e. as long as the code is not already used)
    # There are 2 code gen strategies,
    # - opaque, default, standard SecureRandom string
    # - pkce, for PKCE enabled clients
    def self.generate_id(attributes: {code_type: OPAQUE}, &predicate)
      tuple = case attributes[:code_type]
      when OPAQUE
        [random_string, :random_string]
      when PKCE
        [pkce_string(attributes), :pkce_string]
      else  # Shouldn't get here, but assume opaque
        [random_string, :random_string]
      end
      self.send(tuple[1]) until predicate.call(tuple[0])
    end

    def self.hashify(token)
      return nil unless String === token
      Digest::SHA1.hexdigest(token)
    end

    ACCESS_TOKEN           = 'access_token'
    ASSERTION              = 'assertion'
    ASSERTION_TYPE         = 'assertion_type'
    AUTHORIZATION_CODE     = 'authorization_code'
    CLIENT_CREDENTIALS     = 'client_credentials'
    CLIENT_ID              = 'client_id'
    CLIENT_SECRET          = 'client_secret'
    CODE                   = 'code'
    CODE_AND_TOKEN         = 'code_and_token'
    CODE_CHALLENGE         = 'code_challenge'
    CODE_CHALLENGE_METHOD  = 'code_challenge_method'
    CODE_CHALLENGE_HASH_METHOD = 'S256'
    DURATION               = 'duration'
    ERROR                  = 'error'
    ERROR_DESCRIPTION      = 'error_description'
    EXPIRES_IN             = 'expires_in'
    GRANT_TYPE             = 'grant_type'
    LOGIN_HINT             = 'login_hint'
    OAUTH_TOKEN            = 'oauth_token'
    OPAQUE                 = 'opaque'
    PASSWORD               = 'password'
    PKCE                   = 'pkce'
    REDIRECT_URI           = 'redirect_uri'
    REFRESH_TOKEN          = 'refresh_token'
    RESPONSE_TYPE          = 'response_type'
    SCOPE                  = 'scope'
    STATE                  = 'state'
    TOKEN                  = 'token'
    USERNAME               = 'username'
    INVALID_REQUEST        = 'invalid_request'
    UNSUPPORTED_RESPONSE   = 'unsupported_response_type'
    REDIRECT_MISMATCH      = 'redirect_uri_mismatch'
    UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type'
    INVALID_GRANT          = 'invalid_grant'
    INVALID_CLIENT         = 'invalid_client'
    UNAUTHORIZED_CLIENT    = 'unauthorized_client'
    INVALID_SCOPE          = 'invalid_scope'
    INVALID_TOKEN          = 'invalid_token'
    EXPIRED_TOKEN          = 'expired_token'
    INSUFFICIENT_SCOPE     = 'insufficient_scope'
    ACCESS_DENIED          = 'access_denied'

    class Provider
      EXPIRY_TIME = 3600

      autoload :Authorization, ROOT + '/oauth2/provider/authorization'
      autoload :Exchange,      ROOT + '/oauth2/provider/exchange'
      autoload :AccessToken,   ROOT + '/oauth2/provider/access_token'
      autoload :Error,         ROOT + '/oauth2/provider/error'

      class << self
        attr_accessor :realm, :enforce_ssl
      end

      def self.clear_assertion_handlers!
        @password_handler   = nil
        @client_credentials_handler = nil
        @assertion_handlers = {}
        @assertion_filters  = []
      end

      clear_assertion_handlers!

      def self.handle_passwords(&block)
        @password_handler = block
      end

      def self.handle_password(client, username, password, scopes)
        return nil unless @password_handler
        @password_handler.call(client, username, password, scopes)
      end

      def self.handle_client_credentials(&block)
        @client_credentials_handler = block
      end

      def self.handle_client_credential(client, owner, scopes)
        return nil unless @client_credentials_handler
        @client_credentials_handler.call(client, owner, scopes)
      end

      def self.filter_assertions(&filter)
        @assertion_filters.push(filter)
      end

      def self.handle_assertions(assertion_type, &handler)
        @assertion_handlers[assertion_type] = handler
      end

      def self.handle_assertion(client, assertion, scopes)
        return nil unless @assertion_filters.all? { |f| f.call(client) }
        handler = @assertion_handlers[assertion.type]
        handler ? handler.call(client, assertion.value, scopes) : nil
      end

      def self.parse(*args)
        Router.parse(*args)
      end

      def self.access_token(*args)
        Router.access_token(*args)
      end

      def self.access_token_from_request(*args)
        Router.access_token_from_request(*args)
      end
    end

  end
end
