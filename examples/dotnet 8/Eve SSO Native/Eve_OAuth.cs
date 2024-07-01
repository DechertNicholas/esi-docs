using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Web;

namespace Eve_SSO_Native
{
    public class Eve_OAuth
    {
        private const string callbackUrl = "http://localhost:7966/callback/";
        private const string clientId = "61bc7fae92a948b3b9c5978c001d5729";
        private static readonly List<string> scopes;

        static Eve_OAuth()
        {
            scopes = [
                "publicData",
                "esi-industry.read_character_jobs.v1"
            ];
        }

        public static async Task<AccessToken> Authorize()
        {
            string codeVerifier, codeChallenge, state;
            GenerateChallengeAndState(out codeVerifier, out codeChallenge, out state);

            var authorizationTokenParameters = new Dictionary<string, string>
            {
                { "response_type", "code" },
                { "redirect_uri", HttpUtility.UrlEncode(callbackUrl) },
                { "client_id", clientId },
                { "scope", HttpUtility.UrlEncode(string.Join(" ", scopes)) },
                { "code_challenge", codeChallenge },
                { "code_challenge_method", "S256" },
                { "state", state }
            };

            var code = await SendAuthorizationTokenRequest(authorizationTokenParameters);

            var accessTokenParamaters = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "client_id", clientId },
                { "code", code },
                { "code_verifier", codeVerifier }
            };

            var accessToken = await SendAccessTokenRequest(accessTokenParamaters);

            var validationResult = await ValidateAccessToken(accessToken);
            if (validationResult["IsValid"] == "false")
            {
                throw new Exception($"Validation result failed.\n\n{validationResult["Exception"]}");
            }
            return accessToken;
        }

        private static void GenerateChallengeAndState(out string codeVerifier, out string codeChallenge, out string state)
        {
            var randomBytes = new byte[32];
            RandomNumberGenerator.Fill(randomBytes);
            codeVerifier = Base64UrlEncoder.Encode(randomBytes);
            var challengeHash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
            codeChallenge = Base64UrlEncoder.Encode(challengeHash).Replace("=", "");

            var stateBytes = new byte[16];
            RandomNumberGenerator.Fill(stateBytes);
            state = Base64UrlEncoder.Encode(stateBytes);
        }

        private static async Task<string> SendAuthorizationTokenRequest(Dictionary<string, string> tokenAuthorizationParameters)
        {
            var authorizationEndpoint = "https://login.eveonline.com/v2/oauth/authorize/";

            using (var httpListener = new HttpListener())
            {
                var url = $"{authorizationEndpoint}";
                foreach (var key in tokenAuthorizationParameters.Keys)
                {
                    url += (key == tokenAuthorizationParameters.First().Key) ? "?" : "&";
                    url += $"{key}={tokenAuthorizationParameters[key]}";
                }

                httpListener.Prefixes.Add(callbackUrl);
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });

                httpListener.Start();
                var context = await httpListener.GetContextAsync();

                var responseState = context.Request.QueryString["state"];
                if (responseState != tokenAuthorizationParameters["state"])
                {
                    throw new Exception("Invalid state");
                }

                var code = context.Request.QueryString["code"];

                var response = context.Response;
                var responseString = "<html><body>You can close this window now.</body></html>";
                var buffer = Encoding.UTF8.GetBytes(responseString);
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
                response.OutputStream.Close();
                httpListener.Stop();

                return code;
            }
        }

        private static async Task<AccessToken> SendAccessTokenRequest(Dictionary<string, string> tokenAuthorizationParameters)
        {
            var tokenEndpoint = "https://login.eveonline.com/v2/oauth/token";
            using (var client = new HttpClient())
            {
                var tokenRequestContent = new FormUrlEncodedContent(tokenAuthorizationParameters);
                var tokenResponse = await client.PostAsync(tokenEndpoint, tokenRequestContent);
                var tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();

                var accessTokenResponse = JsonSerializer.Deserialize<AccessTokenResponse>(tokenResponseContent);
                return new AccessToken()
                {
                    WebToken = new JsonWebToken(accessTokenResponse.AccessToken),
                    RefreshToken = accessTokenResponse.RefreshToken
                };
            }
        }

        private static async Task<Dictionary<string, string>> ValidateAccessToken(AccessToken accessToken)
        {
            var ssoMetaDataUrl = "https://login.eveonline.com/.well-known/oauth-authorization-server";
            var jwkAlgorithm = "RS256";
            var jwkIssuers = new List<string>() { "login.eveonline.com", "https://login.eveonline.com" };
            var jwkAudience = "EVE Online";

            using (var client = new HttpClient())
            {
                var metaDataResponse = await client.GetAsync(ssoMetaDataUrl);
                var metaData = JsonNode.Parse(await metaDataResponse.Content.ReadAsStringAsync());
                var jwksUri = metaData["jwks_uri"].ToString();

                var jwksDataResponse = await client.GetAsync(jwksUri);
                var jwksData = JsonObject.Parse(await jwksDataResponse.Content.ReadAsStringAsync()).AsObject()["keys"].AsArray();
                var key = jwksData.Where(k => k["alg"].AsValue().GetValue<string>() == jwkAlgorithm).First();
                if (key == null)
                {
                    throw new Exception("Unable to find a key matching the specified algorithm.");
                }
                var jwk = new JsonWebKey(key.ToJsonString());
                var jwth = new JsonWebTokenHandler();
                var tvp = new TokenValidationParameters()
                {
                    ValidIssuers = jwkIssuers,
                    ValidAudience = jwkAudience,
                    IssuerSigningKey = jwk
                };

                var validation = await jwth.ValidateTokenAsync(accessToken.WebToken, tvp);
                return new Dictionary<string, string>()
                {
                    { "IsValid", validation.IsValid.ToString() },
                    { "Exception", validation.Exception?.Message ?? string.Empty }
                };
            }
        }

        public static async Task<AccessToken> RefreshAccessToken(AccessToken accessToken)
        {
            var url = "https://login.eveonline.com/v2/oauth/token";

            var body = new Dictionary<string, string>()
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", accessToken.RefreshToken },
                { "client_id", clientId }
            };

            var content = new FormUrlEncodedContent(body);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Host = "login.eveonline.com";
                var result = await client.PostAsync(url, content);
                Console.WriteLine(await result.Content.ReadAsStringAsync());
                var token = JsonSerializer.Deserialize<AccessTokenResponse>(await result.Content.ReadAsStringAsync());
                result.EnsureSuccessStatusCode();

                return new AccessToken()
                {
                    WebToken = new JsonWebToken(token.AccessToken),
                    RefreshToken = token.RefreshToken
                };
            }
        }
    }

    public class AccessTokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
    }

    public class AccessToken
    {
        public JsonWebToken WebToken { get; set; }

        public string RefreshToken { get; set; }
    }
}
