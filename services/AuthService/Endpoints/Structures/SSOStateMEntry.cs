/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using AuthService.Endpoints.Common;
using BCloudServiceUtilities;
using Newtonsoft.Json;

namespace AuthService.Endpoints.Structures
{
    public class SSOStateMEntry
    {
        public static BMemoryQueryParameters ID_SSO_STATE_MEMORY_SERVICE_KEY(string _UniqueStateID)
        {
            return new BMemoryQueryParameters()
            {
                Domain = CommonData.MemoryQueryParameters.Domain,
                Identifier = CommonData.MemoryQueryParameters.Identifier,
                SubDomain = _UniqueStateID
            };
        }

        public const string HASH_KEY = "properties";

        public const string SERVERSIDE_REDIRECT_URL_PROPERTY = "serversideRedirectUrl";
        public const string TENANT_NAME_PROPERTY = "tenantName";
        public const string STATUS_PROPERTY = "state";

        [JsonProperty(SERVERSIDE_REDIRECT_URL_PROPERTY)]
        public string ServersideRedirectUrl = "";

        [JsonProperty(TENANT_NAME_PROPERTY)]
        public string TenantName = "";

        [JsonProperty(STATUS_PROPERTY)]
        public string Status = "";

        //States (Values)
        public const string STATUS_AUTHENTICATING = "authenticating";
        public const string STATUS_AUTHORIZING = "authorizing";
    }
}