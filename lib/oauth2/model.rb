require 'active_record'

module OAuth2
  module Model
    autoload :Helpers,       ROOT + '/oauth2/model/helpers'
    autoload :ClientOwner,   ROOT + '/oauth2/model/client_owner'
    autoload :ResourceOwner, ROOT + '/oauth2/model/resource_owner'
    autoload :Hashing,       ROOT + '/oauth2/model/hashing'
    autoload :Authorization, ROOT + '/oauth2/model/authorization'
    autoload :Client,        ROOT + '/oauth2/model/client'

    Schema = OAuth2::Schema

    DUPLICATE_RECORD_ERRORS = [
      /^Mysql::Error:\s+Duplicate\s+entry\b/,
      /^PG::Error:\s+ERROR:\s+duplicate\s+key\b/,
      /\bConstraintException\b/
    ]


    # ActiveRecord::RecordNotUnique was introduced in Rails 3.0 so referring
    # to it while running earlier versions will raise an error. The above
    # error strings should match PostgreSQL, MySQL and SQLite errors on
    # Rails 2. If you're running a different adapter, add a suitable regex to
    # the list:
    #
    #     OAuth2::Model::DUPLICATE_RECORD_ERRORS << /DB2 found a dup/
    #
    def self.duplicate_record_error?(error)
      error.class.name == 'ActiveRecord::RecordNotUnique' or
      DUPLICATE_RECORD_ERRORS.any? { |re| re =~ error.message }
    end

    # This will only return an authorisation for JWT and non-JWT tokens
    # TODO: Refactor this to an access token service (probably exchange)
    def self.find_access_token(token_tuple)
      return nil if token_tuple.nil?
      return nil if Provider.token_decoder.nil? || !Provider.token_decoder[0].respond_to?(Provider.token_decoder[1])
      if token_tuple[0] == :jwt
        begin
          Authorization.find_by_jwt(Provider.token_decoder[0].send(Provider.token_decoder[1], token_tuple[1]))
        rescue JSON::JWT::Exception => e
          nil
        end
      else
        Authorization.find_by_access_token_hash(Lib::SecureCodeScheme.hashify(token_tuple[1]))
      end
    end
  end
end
