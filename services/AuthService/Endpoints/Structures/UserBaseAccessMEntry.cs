/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System.Collections.Generic;
using Newtonsoft.Json;

namespace AuthService.Endpoints.Structures
{
    //Memory service entry
    //KeyName = KEY_NAME_USER_ID
    public class UserBaseAccessMEntry
    {
        public const string M_KEY_NAME_USER_ID = "userIdForBaseAccessCache";

        public const string BASE_ACCESS_SCOPE_PROPERTY = "baseAccessScope";

        public static readonly string[] Properties =
        {
            BASE_ACCESS_SCOPE_PROPERTY
        };

        [JsonProperty(BASE_ACCESS_SCOPE_PROPERTY)]
        public List<AccessScope> BaseAccessScope = new List<AccessScope>();
    }
}