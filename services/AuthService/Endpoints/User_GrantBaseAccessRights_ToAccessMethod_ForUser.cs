/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.Net;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using ServiceUtilities;
using ServiceUtilities.PubSubUsers.PubSubRelated;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService
{
    internal class User_GrantBaseAccessRights_ToAccessMethod_ForUser : WebServiceBaseTimeoutableDeliveryEnsurerUser
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;
        private readonly string RestfulUrlParameter_UsersKey;
        private readonly string RestfulUrlParameter_AccessMethodKey;

        private string RequestedUserID;
        private string RequestedAuthMethodKey;

        public User_GrantBaseAccessRights_ToAccessMethod_ForUser(IBDatabaseServiceInterface _DatabaseService, IBMemoryServiceInterface _MemoryService, string _RestfulUrlParameter_UsersKey, string _RestfulUrlParameter_AccessMethodKey)
        {
            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;
            RestfulUrlParameter_UsersKey = _RestfulUrlParameter_UsersKey;
            RestfulUrlParameter_AccessMethodKey = _RestfulUrlParameter_AccessMethodKey;
        }

        public override BWebServiceResponse OnRequest_Interruptable_DeliveryEnsurerUser(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
        {
            GetTracingService()?.On_FromGatewayToService_Received(_Context, _ErrorMessageAction);

            var Result = OnRequest_Internal(_Context, _ErrorMessageAction);

            GetTracingService()?.On_FromServiceToGateway_Sent(_Context, _ErrorMessageAction);

            return Result;
        }

        private BWebServiceResponse OnRequest_Internal(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
        {
            if (_Context.Request.HttpMethod != "POST")
            {
                _ErrorMessageAction?.Invoke("User_GrantBaseAccessRights_ToAccessMethod_ForUser: POST method is accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("POST method is accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            RequestedUserID = RestfulUrlParameters[RestfulUrlParameter_UsersKey];
            RequestedAuthMethodKey = WebUtility.UrlDecode(RestfulUrlParameters[RestfulUrlParameter_AccessMethodKey]);

            if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Atomic operation control has failed.");
            }

            var Result = GrantBaseAccessRights_ToAccessMethod(_Context, _ErrorMessageAction);

            Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction);

            return Result;
        }

        private BWebServiceResponse GrantBaseAccessRights_ToAccessMethod(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
        {
            var UserKey = new BPrimitiveType(RequestedUserID);
            var AuthDBEntryKey = new BPrimitiveType(RequestedAuthMethodKey);

            if (!DatabaseService.GetItem(
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                UserKey,
                UserDBEntry.Properties,
                out JObject UserObject,
                _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Database fetch operation has failed.");
            }
            if (!UserObject.ContainsKey(UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY))
            {
                return BWebResponse.Forbidden("User does not have any base rights.");
            }

            if (!DatabaseService.GetItem(
                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                AuthDBEntryKey,
                AuthDBEntry.Properties,
                out JObject AuthDBEntryObject,
            _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Database fetch-auth-method-info operation has failed.");
            }
            if (AuthDBEntryObject == null)
            {
                return BWebResponse.NotFound("Given auth method does not exist.");
            }
            var AuthEntry = JsonConvert.DeserializeObject<AuthDBEntry>(AuthDBEntryObject.ToString());

            var BaseScopeList = new List<AccessScope>();
            var BaseScopesArray = (JArray)UserObject[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY];
            foreach (JObject BaseScopeObject in BaseScopesArray)
            {
                BaseScopeList.Add(JsonConvert.DeserializeObject<AccessScope>(BaseScopeObject.ToString()));
            }
            AccessScopeLibrary.CombineRightsOfAccessScopeLists_IntoNew(AuthEntry.FinalAccessScope, BaseScopeList);

            var AuthEntryAsJsonString = JsonConvert.SerializeObject(AuthEntry);
            var AuthEntryAsJsonObject = JObject.Parse(AuthEntryAsJsonString);

            Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                _Context,
                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                AuthDBEntryKey,
                AuthEntryAsJsonObject);

            MemoryService.SetKeyValue(CommonData.MemoryQueryParameters,
                new Tuple<string, BPrimitiveType>[]
                {
                    new Tuple<string, BPrimitiveType>(AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + AuthDBEntryKey.AsString, new BPrimitiveType(AuthEntryAsJsonString))
                },
                _ErrorMessageAction);

            return BWebResponse.StatusOK("Access method has been granted with all base access rights.");
        }
    }
}