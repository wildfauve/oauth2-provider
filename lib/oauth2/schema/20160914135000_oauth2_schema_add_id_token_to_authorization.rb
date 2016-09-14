class Oauth2SchemaAddIdTokenToAuthorization < ActiveRecord::Migration

  def change
    add_column :oauth2_authorizations, :id_token, :string
  end

end
