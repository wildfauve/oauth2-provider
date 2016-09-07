module Songkick

  module OAuth2

    module Lib

      class SecureCodeScheme

        # Generates a SecureRandom string until the predicate is met
        # (i.e. as long as the code is not already used)
        # There are 2 code gen strategies,
        # - opaque, default, standard SecureRandom string
        # - pkce, for PKCE enabled clients

        # e.g
        # code = generate(attributes: {code_type: 'pkce',code_challenge: "", code_challenge_method: "S256"}) {|x| true}
        def generate(attributes: {code_type: OPAQUE}, &predicate)
          tuple = case attributes[:code_type]
          when OPAQUE
            [random_string, :random_string]
          when PKCE
            [pkce_string(attributes), :pkce_string]
          else  # Shouldn't get here, but assume opaque
            [random_string, :random_string]
          end
          id = tuple[0]
          id = send(tuple[1], attributes) until predicate.call(id)
          id
        end

        # A PKCE code is provided.
        # Decrypt with the base cipher and decode the PKCE string into:
        # - code
        # - method
        def pkce_decode_code_and_method(code)
          pkce_code_de_tokenise(pkce_decrypt(code))
        end

        # Take in the verifier that created the code challenge, and the method (usually S256)
        # and produce the original code challenge
        def pkce_run_hash_on_verifier(verifier, method = "S256")
          Base64.urlsafe_encode64(Digest::SHA256.digest(verifier)).chomp("=")
        end


        # Decrypt the auth code originally sent to the relying party
        def pkce_decrypt(code)
          cipher = aes_cipher(:decrypt)
          cipher.update(Base64.urlsafe_decode64(code)) + cipher.final  rescue [nil, nil]
        end


        def random_string(attributes: {})
          if defined? SecureRandom
            SecureRandom.hex(TOKEN_SIZE / 8).to_i(16).to_s(36)
          else
            rand(2 ** TOKEN_SIZE).to_s(36)
          end
        end

        def pkce_string(attributes)
          cipher = aes_cipher(:encrypt)
          Base64.urlsafe_encode64(cipher.update(pkce_tokenise(attributes[CODE_CHALLENGE.to_sym], attributes[CODE_CHALLENGE_METHOD.to_sym])) + cipher.final)
        end

        def aes_cipher(direction)
          cipher = OpenSSL::Cipher::AES.new(256, :CBC)
          cipher.send(direction)
          cipher.key = "bff19d8c59f31f68d70e34abae5c93420c17f50bc3c278878593ced6b03d916d"
          cipher.iv = "aa8dbfb30de9bac490cab3aa551376add3462bb9080e0d534f8301cd094f56a7"
          cipher
        end

        def pkce_tokenise(challenge, method)
          "#{challenge}:#{method}"
        end

        def pkce_code_de_tokenise(string)
          string.split(":")
        end

        def hashify(token)
          return nil unless String === token
          Digest::SHA1.hexdigest(token)
        end



      end

    end

  end

end
