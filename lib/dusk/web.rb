require 'sinatra'
require 'rack-ssl-enforcer'
require 'sinatra_auth_github'
require 'json'
require 'uri'

module Dusk
  class Web < Sinatra::Base
    def authorized?
      @auth ||=  Rack::Auth::Basic::Request.new(request.env)
      @auth.provided? && @auth.basic? && @auth.credentials
    end

    def protected!
      unless authorized?
        response['WWW-Authenticate'] = %(Basic realm="Restricted Area")
        throw(:halt, [401, "Oops... we need your login name & password\n"])
      end
    end

    configure do
      enable :logging
      enable :sessions

      mime_type :js, 'text/javascript'

      use Rack::SslEnforcer if ENV['FORCE_HTTPS']

      set :session_secret, ENV['SESSION_SECRET'] || Digest::SHA1.hexdigest(Time.now.to_f.to_s)
      set :github_options, { :scopes => "user" }

      if ENV['GITHUB_AUTH_TEAM'] || ENV['GITHUB_AUTH_ORGANIZATION']
        register Sinatra::Auth::Github
      end
    end

    before do
      if team = ENV['GITHUB_AUTH_TEAM']
        github_team_authenticate!(team)
      elsif organization = ENV['GITHUB_AUTH_ORGANIZATION']
        github_organization_authenticate!(organization)
      else
        protected!
      end
      session[:favorites] ||= []
    end

    get '/' do
      erb :index, :locals => { :favorites => session[:favorites] }
    end

    get '/metrics/find' do
      username, password = @auth.credentials
      uri = URI("#{ENV['GRAPHITE_URL']}#{request.env['REQUEST_URI']}")
      uri.user = username
      uri.password = password
      begin
        RestClient.get(uri.to_s)
      rescue
        @auth = nil
      end
    end

    get '/render/?' do
      username, password = @auth.credentials
      uri = URI("#{ENV['GRAPHITE_URL']}#{request.env['REQUEST_URI']}")
      uri.user = username
      uri.password = password
      begin
        RestClient.get(uri.to_s)
      rescue
        @auth = nil
      end
    end

    get %r{/metrics/(\S+)} do |metric|
      erb :index, :locals => { :target => URI.encode(metric), :index => params[:index] }
    end

    get '/favorites/?' do
      status 200
      session[:favorites].to_json
    end

    post %r{/favorites/(\S+)} do |metric|
      session[:favorites].push(metric) unless session[:favorites].include?(metric)
      status 204
    end

    delete %r{/favorites/(\S+)} do |metric|
      if session[:favorites].include?(metric)
        session[:favorites].delete(metric)
        status 204
      else
        status 404
      end
    end
  end
end
