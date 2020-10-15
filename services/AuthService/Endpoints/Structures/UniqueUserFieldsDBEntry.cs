/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using ServiceUtilities;

namespace AuthService.Endpoints.Structures
{
    //DB Table entry
    //KeyName = UserDBEntry.USER_NAME_PROPERTY
    //or
    //KeyName = UserDBEntry.USER_EMAIL_PROPERTY
    //or
    //KeyName = AuthMethod.API_KEY_PROPERTY
    public class UniqueUserFieldsDBEntry
    {
        public static string DBSERVICE_UNIQUEUSERFIELDS_TABLE() { return "unique-user-fields-" + Resources_DeploymentManager.Get().GetDeploymentBranchNameEscapedLoweredWithDash(); }

        public const string KEY_NAME_USER_EMAIL = UserDBEntry.USER_EMAIL_PROPERTY;
        public const string KEY_NAME_USER_NAME = UserDBEntry.USER_NAME_PROPERTY;
        public const string KEY_NAME_API_KEY = AuthMethod.API_KEY_PROPERTY;

        public static readonly string[] Properties = 
        {
            UserDBEntry.KEY_NAME_USER_ID
        };
    }
}
