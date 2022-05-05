require 'omniauth'

module OmniAuth
  module Strategies
    class Speakap
      class SpeakapError < StandardError; end

      include OmniAuth::Strategy

      option :speakap_secret_key, nil
      option :speakap_app_id, nil
      option :speakap_network_eid, nil

      option :auth_url, ""

      def request_phase
        redirect options.auth_url
      end

      def authenticate_speakap
        raise "Only POST request is allowed" unless request.post?

        log :info, "SPEAKAP: Auth flow at #{Time.now}"

        log :info, "NETWORK #{options.speakap_network_eid}"
        log :info, "SECRET #{options.speakap_secret_key}"
        log :info, "APPID #{options.speakap_app_id}"
        log :info, "APP #{options.app}" if options.has_key?('app')

        # 1. Check for time based replay attacks
        # Here we should check the auth of speakap
        raise "issuedAt not given" unless speakap_params["issuedAt"]
        issued        = Time.parse(speakap_params["issuedAt"])
        expires_at    = issued + 60.seconds

        log :info, "SPEAKAP: Check time #{issued} expires: #{expires_at}"
        raise "Speakap auth expired, issued: #{issued} expired_at: #{expires_at}" if Time.now > expires_at

        # 2. Check the signature that with the secret we get
        # from the secret set in the options
        speakap_hash = speakap_params.to_h.without(:app).without('app').without(:connector).without('connector')
        signature    = speakap_hash.delete("signature")

        log :info, "Params hash"
        log :info, speakap_hash.inspect

        log :info, "Given signature"
        log :info, signature

        log :info, "Given query"
        query = Rack::Utils.build_query(speakap_hash)        
        log :info, "Query is: #{query}"


        query = speakap_hash.to_query        
        log :info, "Query2 is: #{query}"

        log :info, "Generated signature"
        generated_signature = Base64.strict_encode64(OpenSSL::HMAC.digest(
          OpenSSL::Digest.new('sha256'), options.speakap_secret_key, query))

        log :info, "Signature is: #{generated_signature}, given signature: #{signature}"

        # 3. Ensure that the signature is time constant
        # checked to prevent invasion of martians.
        raise "SPEAKAP: Speakap no sig match" unless ActiveSupport::SecurityUtils.secure_compare(generated_signature, signature)
      end

      def without(*keys)
        cpy = self.dup
        keys.each { |key| cpy.delete(key) }
        cpy
      end

      def speakap_params
        request.params
      end

      def callback_phase
        authenticate_speakap
        super
      rescue SpeakapError => e
        fail! :speakap_error, e
      end

      uid {
        request.params["userEID"]
      }

      extra do
        {
          :raw_info => speakap_params
        }
      end

      info do
        speakap = ::Speakap::Api.new(options.speakap_network_eid, options.speakap_app_id, options.speakap_secret_key)
        speakap.get_user_by_eid(request.params["userEID"])
      end
    end
  end
end