class Oauth2SchemaAddProductToClient < ActiveRecord::Migration

  def change
    add_column :oauth2_clients, :product_experience, :string, size: 30
  end

end
