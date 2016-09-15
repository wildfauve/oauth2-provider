require 'spec_helper'

describe OAuth2::Provider::Authorization do
  let(:resource_owner) { TestApp::User['Bob'] }

  let(:authorization) { OAuth2::Provider::Authorization.new(resource_owner, params) }

  let(:params) { { 'response_type' => 'code',
                   'code_challenge' => "challenge",
                   'client_id' => @client.client_id,
                   'code_challenge_method' => 'S256',
                   'redirect_uri'  => @client.redirect_uri }
               }

  before do
    @client = Factory(:native_client)
    allow(OAuth2::Lib::SecureCodeScheme).to receive(:generate).and_return('pkcs_code')
  end

  describe "providing an authorisation with valid native app parameters" do
    it "is valid" do
      expect(authorization.error).to be_nil
    end

  end

  describe "invalid native app parameters" do

    it 'should return an error when a code and challenge is not provided' do
      invalid_native_params = { 'response_type' => 'code',
                                'client_id' => @client.client_id,
                                'redirect_uri'  => @client.redirect_uri
                              }
      auth = OAuth2::Provider::Authorization.new(resource_owner, invalid_native_params)

      expect(auth.error).to_not be nil
      expect(auth.error_description).to match /\[:code_challenge, :code_challenge_method\]/

    end

  end

end
