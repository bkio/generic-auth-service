/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using BCloudServiceUtilities;
using AuthService.Endpoints.Common;
using Newtonsoft.Json;
using BCommonUtilities;
using System.Collections.Generic;

namespace AuthService.Endpoints.Structures
{
    class InternalSetState
    {
        public static readonly BMemoryQueryParameters ID_INTERNAL_SET_MEMORY_SERVICE_KEY = new BMemoryQueryParameters()
        {
            Domain = CommonData.MemoryQueryParameters.Domain,
            Identifier = CommonData.MemoryQueryParameters.Identifier,
            SubDomain = HASH_KEY
        };

        public const string HASH_KEY = "internal";

        public const string API_GATEWAY_PUBLIC_URL_PROPERTY = "gatewayPublicUrl";

        [JsonProperty(API_GATEWAY_PUBLIC_URL_PROPERTY)]
        public string ApiGatewayPublicUrl = "";

        private static readonly Dictionary<string, string> CachedPropertiesAfterFirstGet = new Dictionary<string, string>();

        public static bool GetValueFromMemoryService(out string _Value, string _Key, IBMemoryServiceInterface _MemoryService, Action<string> _ErrorMessageAction)
        {
            if (CachedPropertiesAfterFirstGet.ContainsKey(_Key))
            {
                _Value = CachedPropertiesAfterFirstGet[_Key];
                return true;
            }

            _Value = null;

            var ValuePrimitive = _MemoryService.GetKeyValue(ID_INTERNAL_SET_MEMORY_SERVICE_KEY, _Key, _ErrorMessageAction);
            if (ValuePrimitive == null)
            {
                _ErrorMessageAction?.Invoke("InternalSetState memory service has failed to get " + _Key);
                return false;
            }
            else
            {
                _Value = ValuePrimitive.AsString;
                CachedPropertiesAfterFirstGet[_Key] = _Value;
            }

            return true;
        }

        public static bool SetValueToMemoryService(string _Key, string _Value, IBMemoryServiceInterface _MemoryService, Action<string> _ErrorMessageAction)
        {
            if (!_MemoryService.SetKeyValue(
                ID_INTERNAL_SET_MEMORY_SERVICE_KEY,
                new Tuple<string, BPrimitiveType>[]
                {
                        new Tuple<string, BPrimitiveType>(_Key, new BPrimitiveType(_Value))
                },
                _ErrorMessageAction))
            {
                _ErrorMessageAction?.Invoke("Internal Set State ID generation has failed.");
                return false;
            }
            return true;
        }
    }
}