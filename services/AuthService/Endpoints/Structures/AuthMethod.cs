/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using Newtonsoft.Json;

namespace AuthService.Endpoints.Structures
{
    public class AuthMethod
    {
        public const string METHOD_PROPERTY = "method";
        public static class Methods
        {
            public const string API_KEY_METHOD = "apiKeyMethod";
            public const string USER_EMAIL_PASSWORD_METHOD = "userEmailPasswordMethod";
            public const string USER_NAME_PASSWORD_METHOD = "userNamePasswordMethod";
        }

        public const string API_KEY_PROPERTY = "apiKey";
        public const string USER_NAME_PROPERTY = UserDBEntry.USER_NAME_PROPERTY;
        public const string USER_EMAIL_PROPERTY = UserDBEntry.USER_EMAIL_PROPERTY;

        public const string PASSWORD_MD5_PROPERTY = "passwordMd5";

        [JsonProperty(METHOD_PROPERTY)]
        public string Method = "";

        //Only used for Method = Methods.API_KEY_METHOD
        [JsonProperty(API_KEY_PROPERTY)]
        public string ApiKey = "";

        //Only used for Method = Methods.USER_EMAIL_PASSWORD_METHOD
        [JsonProperty(USER_EMAIL_PROPERTY)]
        public string UserEmail = "";

        //Only used for Method = Methods.USER_NAME_PASSWORD_METHOD
        [JsonProperty(USER_NAME_PROPERTY)]
        public string UserName = "";

        //Only used for Method = Methods.USER_EMAIL_PASSWORD_METHOD | Methods.USER_NAME_PASSWORD_METHOD
        [JsonProperty(PASSWORD_MD5_PROPERTY)]
        public string PasswordMD5 = "";

        public bool CompareWith(AuthMethod _Other, bool _bCheckPasswordMD5_IfAvailable)
        {
            if (_Other == null) return false;
            if (Method != _Other.Method) return false;

            switch (Method)
            {
                case Methods.API_KEY_METHOD:
                    return ApiKey == _Other.ApiKey;
                case Methods.USER_EMAIL_PASSWORD_METHOD:
                    return UserEmail == _Other.UserEmail
                        && (!_bCheckPasswordMD5_IfAvailable || PasswordMD5 == _Other.PasswordMD5);
                case Methods.USER_NAME_PASSWORD_METHOD:
                    return UserName == _Other.UserName
                        && (!_bCheckPasswordMD5_IfAvailable || PasswordMD5 == _Other.PasswordMD5);
                default:
                    return false;
            }
        }
    }
}