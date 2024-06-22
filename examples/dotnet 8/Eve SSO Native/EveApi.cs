using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Eve_SSO_Native
{
    public static class EveApi
    {
        private static HttpClient Client = new();
        private static string ApiUrlBase = "https://esi.evetech.net/latest/";

        // in a real application, you should get the accessToken from a database or other storage, not by parameter
        public static async Task GetIndustryJobs(AccessToken accessToken)
        {
            var characterId = accessToken.WebToken.Subject.Split(':')[2];
            var url = ApiUrlBase + $"characters/{characterId}/industry/jobs/";
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken.WebToken.EncodedToken);

            var result = await Client.SendAsync(request);
            result.EnsureSuccessStatusCode();
        }
    }
}
