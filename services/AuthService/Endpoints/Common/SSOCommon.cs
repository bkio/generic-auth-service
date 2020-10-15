/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System.Collections.Generic;
using System.Net;
using BCommonUtilities;
using BWebServiceUtilities;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints.Common
{
    public class SSOCommon
    {
        public const string SCOPE = "openid email offline_access";
        public const string SCOPE_URL_ENCODED = "openid%20email%20offline_access";

        public static BWebServiceResponse MakeCallerRedirected(
            string _PlainRedirectUrlBase,
            bool _bFailure,
            int _FailureStatusCode,
            string _FailureMessage,
            string _SuccessUserID = null,
            string _SuccessPlainAccessTokenWithType = null)
        {
            var FinalRedirectLocation = _PlainRedirectUrlBase;
            FinalRedirectLocation +=
                _bFailure ? ("?error_message=" + WebUtility.UrlEncode("Error " + _FailureStatusCode + ": " + _FailureMessage))
                : ((_SuccessUserID != null && _SuccessPlainAccessTokenWithType != null) ? ("?user_id=" + _SuccessUserID + "&token=" + WebUtility.UrlEncode(_SuccessPlainAccessTokenWithType)) : "");
            return new BWebServiceResponse(
                303, //https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/303
                new Dictionary<string, IEnumerable<string>>()
                {
                    ["location"] = new string[] { FinalRedirectLocation }
                },
                new BStringOrStream(new JObject()
                {
                    ["result"] = _bFailure ? "failure " : "success"
                }.ToString()),
                "application/json");
        }
    }
}