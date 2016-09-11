class Oauth2SchemaChangeLimitOnCode < ActiveRecord::Migration
  def self.up
    change_column :oauth2_authorizations, :code, :string, :limit => 200
  end

  def self.down
    change_column :oauth2_authorizations, :code, :string, :limit => 40
  end
end
