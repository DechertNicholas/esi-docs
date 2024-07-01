using System;

namespace Eve_SSO_Native
{
    internal class Program
    {
        private static AccessToken Token { get; set; } = new();

        static async Task Main(string[] args)
        {
            Token = await Eve_OAuth.Authorize();

            await EveApi.GetIndustryJobs(Token);

            Token = await RefreshToken();
        }

        public static async Task<AccessToken> RefreshToken()
        {
            return await Eve_OAuth.RefreshAccessToken(Token);
        }
    }
}