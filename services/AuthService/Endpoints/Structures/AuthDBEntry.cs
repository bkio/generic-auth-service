/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System.Collections.Generic;
using ServiceUtilities;
using Newtonsoft.Json;

namespace AuthService.Endpoints.Structures
{
    /// <summary>
    /// DB Table entry:
    /// KeyName = KEY_NAME_AUTH_DB_ENTRY_ID
    /// </summary>
    public class AuthDBEntry
    {
        public static string DBSERVICE_AUTHMETHODS_TABLE() { return "auth-methods-" + Resources_DeploymentManager.Get().GetDeploymentBranchNameEscapedLoweredWithDash(); }

        public const string KEY_NAME_AUTH_DB_ENTRY = "credential";

        public const string USER_ID_PROPERTY = UserDBEntry.KEY_NAME_USER_ID;
        public const string USER_NAME_PROPERTY = UserDBEntry.USER_NAME_PROPERTY;
        public const string USER_EMAIL_PROPERTY = UserDBEntry.USER_EMAIL_PROPERTY;

        public static AuthDBEntry MakeNewFromUserDBEntry(string _UserID, UserDBEntry _UserEntry)
        {
            return new AuthDBEntry()
            {
                UserID = _UserID,
                UserEmail = _UserEntry.UserEmail,
                UserName = _UserEntry.UserName
            };
        }

        public static readonly string[] Properties =
        {
            USER_ID_PROPERTY,
            USER_NAME_PROPERTY,
            USER_EMAIL_PROPERTY
        };

        /// <summary>
        /// Update user info call can change these fields.
        /// </summary>
        public static readonly string[] UpdatableProperties = UserDBEntry.UpdatableProperties;

        [JsonProperty(USER_ID_PROPERTY)]
        public string UserID = "";

        [JsonProperty(USER_NAME_PROPERTY)]
        public string UserName = "";

        [JsonProperty(USER_EMAIL_PROPERTY)]
        public string UserEmail = "";
    }
}