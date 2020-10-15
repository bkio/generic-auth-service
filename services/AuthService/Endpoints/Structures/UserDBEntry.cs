/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using BCommonUtilities;
using ServiceUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints.Structures
{
    //DB Table entry
    //KeyName = KEY_NAME_USER_ID
    public class UserDBEntry
    {
        public static string DBSERVICE_USERS_TABLE() { return "users-" + Resources_DeploymentManager.Get().GetDeploymentBranchNameEscapedLoweredWithDash(); }

        public const string KEY_NAME_USER_ID = "userId";

        public const string USER_NAME_PROPERTY = "userName";
        public const string USER_EMAIL_PROPERTY = "userEmail";
        public const string AUTH_METHODS_PROPERTY = "authMethods";
        public const string BASE_ACCESS_SCOPE_PROPERTY = "baseAccessScope";
        public const string USER_MODELS_PROPERTY = "userModels";
        public const string USER_SHARED_MODELS_PROPERTY = "userSharedModels";

        //All fields
        public static readonly string[] Properties =
        {
            USER_NAME_PROPERTY,
            USER_EMAIL_PROPERTY,
            AUTH_METHODS_PROPERTY,
            BASE_ACCESS_SCOPE_PROPERTY,
            USER_MODELS_PROPERTY,
            USER_SHARED_MODELS_PROPERTY
        };

        private const string EmailRegexVal = @"\A(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\Z";
        
        //Update user info call can change these fields.
        public static readonly string[] UpdatableProperties =
        {
            USER_NAME_PROPERTY,
            USER_EMAIL_PROPERTY
        };
        public static readonly Dictionary<string, Func<JToken, bool>> UpdatablePropertiesValidityCheck = new Dictionary<string, Func<JToken, bool>>()
        {
            [USER_NAME_PROPERTY] = (JToken _Parameter) =>
            {
                if (_Parameter.Type != JTokenType.String) return false;

                return ((string)_Parameter).Length > 0;
            },
            [USER_EMAIL_PROPERTY] = (JToken _Parameter) =>
            {
                if (_Parameter.Type != JTokenType.String) return false;

                return Regex.IsMatch((string)_Parameter, EmailRegexVal, RegexOptions.IgnoreCase);
            }
        };

        //For creating a new user; these properties should also exist in UpdatableProperties
        public static readonly string[] MustHaveProperties =
        {
            USER_EMAIL_PROPERTY
        };

        public static bool GenerateUserID(out string _NewUserID, Action<string> _ErrorMessageAction)
        {
            return BUtility.CalculateStringMD5(BUtility.RandomString(32, true), out _NewUserID, _ErrorMessageAction);
        }

        //Get user info call can get these fields.
        public static readonly string[] GetableProperties =
        {
            USER_NAME_PROPERTY,
            USER_EMAIL_PROPERTY,
            USER_MODELS_PROPERTY,
            USER_SHARED_MODELS_PROPERTY
        };

        [JsonProperty(USER_NAME_PROPERTY)]
        public string UserName = "";

        [JsonProperty(USER_EMAIL_PROPERTY)]
        public string UserEmail = "";

        [JsonProperty(AUTH_METHODS_PROPERTY)]
        public List<AuthMethod> AuthMethods = new List<AuthMethod>();

        [JsonProperty(BASE_ACCESS_SCOPE_PROPERTY)]
        public List<AccessScope> BaseAccessScope = new List<AccessScope>();

        [JsonProperty(USER_MODELS_PROPERTY)]
        public List<string> UserModels = new List<string>();

        [JsonProperty(USER_SHARED_MODELS_PROPERTY)]
        public List<string> UserSharedModels = new List<string>();
    }
}