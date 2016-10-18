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


module OAuth2
  ROOT = File.expand_path(File.dirname(__FILE__) + '/..')
  TOKEN_SIZE = 160

  autoload :Model,  ROOT + '/oauth2/model'
  autoload :Router, ROOT + '/oauth2/router'
  autoload :Schema, ROOT + '/oauth2/schema'
  autoload :Lib,    ROOT + '/oauth2/lib'

  ACCESS_TOKEN           = 'access_token'
  ASSERTION              = 'assertion'
  ASSERTION_TYPE         = 'assertion_type'
  AUTHORIZATION_CODE     = 'authorization_code'
  CLIENT_CREDENTIALS     = 'client_credentials'
  CLIENT_ID              = 'client_id'
  CLIENT_SECRET          = 'client_secret'
  CLIENT_TYPE            = 'client_type'
  NATIVE_APP             = 'native_app'
  CLIENT_TYPES           = [NATIVE_APP]
  CODE                   = 'code'
  CODE_AND_TOKEN         = 'code_and_token'
  CODE_CHALLENGE         = 'code_challenge'
  CODE_CHALLENGE_METHOD  = 'code_challenge_method'
  CODE_CHALLENGE_HASH_METHOD = 'S256'
  CODE_VERIFIER          = 'code_verifier'
  DURATION               = 'duration'
  ERROR                  = 'error'
  ERROR_DESCRIPTION      = 'error_description'
  EXPIRES_IN             = 'expires_in'
  GRANT_TYPE             = 'grant_type'
  ID_TOKEN               = 'id_token'
  JWT_ALG                = :RS256  #RSASSA-PKCS1-v1_5 using SHA-256
  LOGIN_HINT             = 'login_hint'
  OAUTH_TOKEN            = 'oauth_token'
  OPAQUE                 = 'opaque'
  PASSWORD               = 'password'
  PKCE                   = 'pkce'
  PRIVATE_KEY            = 'IDENTITY_JWT_PRIVATE_KEY'
  REDIRECT_URI           = 'redirect_uri'
  REFRESH_TOKEN          = 'refresh_token'
  RESPONSE_TYPE          = 'response_type'
  SCOPE                  = 'scope'
  SCOPES                 = 'scopes'
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
  # SecureCode             = Lib::SecureCodeScheme

  class Provider
    EXPIRY_TIME = 3600

    autoload :Authorization, ROOT + '/oauth2/provider/authorization'
    autoload :Exchange,      ROOT + '/oauth2/provider/exchange'
    autoload :AccessToken,   ROOT + '/oauth2/provider/access_token'
    autoload :Error,         ROOT + '/oauth2/provider/error'
    autoload :AuthHandler,   ROOT + '/oauth2/provider/auth_handler'

    class << self
      attr_accessor :realm, :enforce_ssl, :default_duration, :token_decoder
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
