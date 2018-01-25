local setmetatable = setmetatable
local len = string.len
local http_ng = require "resty.http_ng"
local resty_url = require 'resty.url'
local jwt = require 'resty.jwt'
local cjson = require 'cjson'
local backend_client = require ('backend_client')
local env = require 'resty.env'
local http_authorization = require 'resty.http_authorization'
local getenv = os.getenv

local _M = {
  _VERSION = '0.1'
}
local mt = {
  __index = _M
}

-- Required params for each grant type and response type.
_M.params = {
  grant_type = {
    ['authorization_code'] = {'client_id','redirect_uri','code'},
    ['password'] = {'client_id','client_secret','username','password'},
    ['client_credentials'] = {'client_id','client_secret'}
  },
  response_type = {
    ['code'] = {'client_id','redirect_uri'},
    ['token'] = {'client_id','redirect_uri'},
    ['token id_token'] = {'client_id','redirect_uri'},
  }
}

local function timestamp_to_seconds_from_now(expiry)
  local time_now = ngx.now()
  local ttl = expiry and (expiry - time_now) or nil
  return ttl
end

-- Formats the realm public key string into Public Key File (PKCS#8) format
local function format_public_key(key)
  local formatted_key = "-----BEGIN PUBLIC KEY-----\n"
  local key_len = len(key)
  for i=1,key_len,64 do
    formatted_key = formatted_key..string.sub(key, i, i+63).."\n"
  end
  formatted_key = formatted_key.."-----END PUBLIC KEY-----"
  return formatted_key
end


local function get_public_key(forgerock_public_key)

  local key = getenv('FORGEROCK_PUBLIC_KEY')

  ngx.log(ngx.DEBUG, 'forgerock public key: ', key)

  if not key then
    return nil, 'missing key'
  end

  return format_public_key(key)
end

function _M.enabled()
  return env.get('FORGEROCK_ENDPOINT')
end

function _M.enabled()
  return env.get('FORGEROCK_PUBLIC_KEY')
end

function _M.enabled()
  return env.get('FORGEROCK_REALM')
end

function _M.load_configuration(client)
  local endpoint = env.get('FORGEROCK_ENDPOINT')
  local forgerock_realm = getenv('FORGEROCK_REALM')

  if not endpoint then
    return nil, 'missing endpoint configuration'
  end

  if not forgerock_realm then
    return nil, 'missing realm'
  end

  local http_client = http_ng.new{
    backend = client,
    options = {
      ssl = { verify = env.enabled('OPENSSL_VERIFY') }
    }
  }

  local forgerock_config = {
    endpoint = endpoint,
    forgerock_public_key = forgerock_public_key,
    forgerock_realm = forgerock_realm,
    authorize_url = resty_url.join(endpoint,'/oauth2/authorize'),
    token_url = resty_url.join(endpoint,'/oauth2/access_token', '?', 'realm=',forgerock_realm),
    public_key = get_public_key(forgerock_public_key)
  }
  
  return forgerock_config
end

function _M.new(configuration)
  return setmetatable({
    config = configuration
    }, mt)
end

function _M.respond_and_exit(status, body, headers)
  -- TODO: is there a better way to populate the response headers?..
  if headers then
    for name,value in pairs(headers) do
      ngx.header[name] = value
    end
  end

  ngx.status = status
  ngx.print(body)
  ngx.exit(ngx.HTTP_OK)
end

function _M.respond_with_error(status, message)

  --TODO: as per the RFC (https://tools.ietf.org/html/rfc6749#section-5.2) return WWW-Authenticate response header if 401
  local headers = {
    ['Content-Type'] = 'application/json;charset=UTF-8'
  }
  local err_msg = { error = message }
  local body = cjson.encode(err_msg)
  _M.respond_and_exit(status, body, headers)
end

function _M.authorize_check_params(params)
  local response_type = params.response_type
  local required_params = _M.params.response_type
  if not response_type then return false, 'invalid_request' end
  if not required_params[response_type] then return false, 'unsupported_response_type' end

  for _,v in ipairs(required_params[response_type]) do
    if not params[v] then
      return false, 'invalid_request'
    end
  end

  return true
end

function _M.token_check_params(params)
  local grant_type = params.grant_type
  local required_params = _M.params.grant_type
  if not grant_type then return false, 'invalid_request' end
  if not required_params[grant_type] then return false, 'unsupported_grant_type' end

  for _,v in ipairs(required_params[grant_type]) do
    if not params[v] then
      return false, 'invalid_request'
    end
  end
  return true
end

-- Get the headers which will be passed to Keycloak on the token request,
-- currently only passing the Authorization header used for the client authentication
function _M.token_get_headers()
  return { ['Authorization'] = ngx.var.http_authorization }
end

-- Parses the token - in this case we assume it's a JWT token
-- Here we can extract authenticated user's claims or other information returned in the access_token
-- or id_token by RH SSO
local function parse_and_verify_token(self, jwt_token)
  
  local jwt_obj = jwt:verify(self.config.public_key, jwt_token)

  if not jwt_obj.verified then
    ngx.log(ngx.INFO, "[jwt] failed verification for token, reason: ", jwt_obj.reason)
    return jwt_obj, "JWT not verified"
  end

  return jwt_obj
end

function _M.get_client_credentials(req_body)
  local auth = http_authorization.new(ngx.var.http_authorization)
  local params = {
    client_id = auth.userid or req_body.client_id,
    client_secret = auth.password or req_body.client_secret
  }
  return params
end

function _M:transform_credentials(credentials)
  local jwt_obj, err = parse_and_verify_token(self, credentials.access_token)

    if err then
      return nil, nil, err
    end

    if jwt_obj.payload then
      local app_id = jwt_obj.payload.aud
      local ttl = timestamp_to_seconds_from_now(jwt_obj.payload.exp)

      ------
      -- oauth credentials for keycloak
      -- @field app_id Client id
      -- @table credentials_oauth
      return { app_id = app_id }, ttl
    end
end

function _M.check_credentials(service, params)
  local backend = backend_client:new(service)

  local args = {
      app_id = params.client_id,
      app_key = params.client_secret,
      redirect_uri = params.redirect_uri
    }

  local res = backend:authorize(args)

  return res.status == 200
end

function _M:authorize(service, client)
  local ok, err

  local http_client = http_ng.new{
    backend = client,
    options = {
      ssl = { verify = env.enabled('OPENSSL_VERIFY') }
    }
  }

  local params = ngx.req.get_uri_args()

  ok, err = _M.authorize_check_params(params)
  if not ok then
    _M.respond_with_error(400, err)
    return
  end

  ok = _M.check_credentials(service, params)
  if not ok then
    _M.respond_with_error(401, 'invalid_client')
    return
  end

  local url = resty_url.join(self.config.authorize_url, ngx.var.is_args, ngx.var.args)
  local res = http_client.get(url)

  _M.respond_and_exit(res.status, res.body, res.headers)
end

function _M:get_token(service, client)
  local ok, err

  local http_client = http_ng.new{
    backend = client,
    options = {
      ssl = { verify = env.enabled('OPENSSL_VERIFY') }
    }
  }

  ngx.req.read_body()
  local params = ngx.req.get_post_args()

  local creds = _M.get_client_credentials(params)

  params.client_id = creds.client_id
  params.client_secret = creds.client_secret

  ok, err = _M.token_check_params(params)
  if not ok then
    _M.respond_with_error(400, err)
    return
  end

  ok = _M.check_credentials(service, params)
  if not ok then
    _M.respond_with_error(401, 'invalid_client')
    return
  end

  -- call Keycloak authorize
  local url = self.config.token_url

  local res = http_client.post(url, ngx.req.get_post_args(), { headers = _M.token_get_headers() })

  _M.respond_and_exit(res.status, res.body, res.headers)
end

function _M.callback()
  return
end

return _M
