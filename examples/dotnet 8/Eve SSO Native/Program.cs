using System;

namespace Eve_SSO_Native
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var accessToken = await Eve_OAuth.Authorize();

            await EveApi.GetIndustryJobs(accessToken);
        }
    }
}