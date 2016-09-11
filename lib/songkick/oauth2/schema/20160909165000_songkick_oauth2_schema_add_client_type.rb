class Oauth2SchemaAddClientType < ActiveRecord::Migration

  def change
    add_column :oauth2_clients, :client_type, :string
  end

end
