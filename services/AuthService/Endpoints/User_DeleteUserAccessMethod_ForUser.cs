/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.Net;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Controllers;
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
    internal class User_DeleteUserAccessMethod_ForUser : WebServiceBaseTimeoutableDeliveryEnsurerUser
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;
        private readonly string RestfulUrlParameter_UsersKey;
        private readonly string RestfulUrlParameter_AccessMethodKey;

        private string RequestedUserID;
        private string RequestedAuthMethodKey;

        public User_DeleteUserAccessMethod_ForUser(IBDatabaseServiceInterface _DatabaseService, IBMemoryServiceInterface _MemoryService, string _RestfulUrlParameter_UsersKey, string _RestfulUrlParameter_AccessMethodKey)
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

        private bool bIsInternalCall;

        private BWebServiceResponse OnRequest_Internal(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
        {
            bIsInternalCall =
                BWebUtilities.DoesContextContainHeader(out List<string> ICHVs, out string _, _Context, "internal-call-secret")
                && BUtility.CheckAndGetFirstStringFromList(ICHVs, out string ICH)
                && ICH == CommonData.INTERNAL_CALL_PRIVATE_KEY;

            if (_Context.Request.HttpMethod != "DELETE")
            {
                _ErrorMessageAction?.Invoke("User_DeleteUserAccessMethod_ForUser: DELETE method is accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("DELETE methods is accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            RequestedUserID = RestfulUrlParameters[RestfulUrlParameter_UsersKey];
            RequestedAuthMethodKey = WebUtility.UrlDecode(RestfulUrlParameters[RestfulUrlParameter_AccessMethodKey]);

            if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Atomic operation control has failed.");
            }

            var Result = DeleteAccessMethodForUser(_Context, out bool bSetClearanceForApiKey, out string ApiKey, _ErrorMessageAction);

            Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction);
            if (bSetClearanceForApiKey)
            {
                Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_API_KEY + ":" + ApiKey, _ErrorMessageAction);
            }

            return Result;
        }

        //TODO: If SSO is enabled for user; when it loses access to the tenant, delete all rights but keep the models and user.
        private BWebServiceResponse DeleteAccessMethodForUser(HttpListenerContext _Context, out bool _bSetClearanceForApiKey, out string _ApiKey, Action<string> _ErrorMessageAction)
        {
            _bSetClearanceForApiKey = false;
            _ApiKey = null;

            var UserKey = new BPrimitiveType(RequestedUserID);

            if (!DatabaseService.GetItem(
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                UserKey,
                UserDBEntry.Properties,
                out JObject UserObject,
                _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Database fetch-user-info operation has failed.");
            }
            if (UserObject == null)
            {
                return BWebResponse.NotFound("User does not exist.");
            }

            if (!UserObject.ContainsKey(UserDBEntry.AUTH_METHODS_PROPERTY))
            {
                return BWebResponse.NotFound("User does not have any auth method.");
            }

            bool bFound = false;

            var AuthMethodsArray = (JArray)UserObject[UserDBEntry.AUTH_METHODS_PROPERTY];
            for (var i = (AuthMethodsArray.Count - 1); i >= 0; i--)
            {
                var MethodObject = (JObject)AuthMethodsArray[i];
                var Method = JsonConvert.DeserializeObject<AuthMethod>(MethodObject.ToString());

                string AuthMethodKey = null;
                switch (Method.Method)
                {
                    case AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD:
                        {
                            if (!bIsInternalCall && Method.UserEmail.EndsWith(Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX))
                            {
                                return BWebResponse.BadRequest("This auth method cannot be deleted.");
                            }
                            AuthMethodKey = Method.UserEmail + Method.PasswordMD5;
                            break;
                        }
                    case AuthMethod.Methods.USER_NAME_PASSWORD_METHOD:
                        {
                            AuthMethodKey = Method.UserName + Method.PasswordMD5;
                            break;
                        }
                    case AuthMethod.Methods.API_KEY_METHOD:
                        {
                            AuthMethodKey = Method.ApiKey;

                            _bSetClearanceForApiKey = true;
                            _ApiKey = Method.ApiKey;

                            if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_API_KEY + ":" + Method.ApiKey, _ErrorMessageAction))
                            {
                                return BWebResponse.InternalError("Atomic operation control has failed.");
                            }
                            break;
                        }
                }

                if (AuthMethodKey == RequestedAuthMethodKey)
                {
                    AuthMethodsArray.RemoveAt(i);
                    bFound = true;
                }
            }

            if (!bFound)
            {
                return BWebResponse.NotFound("Auth method does not exist.");
            }

            //Update UserDBEntry
            Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                _Context,
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                UserKey,
                UserObject);

            //Delete AuthDBEntry
            Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                _Context,
                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                new BPrimitiveType(RequestedAuthMethodKey));

            if (_bSetClearanceForApiKey)
            {
                //Delete ApiKey from UniqueUserFields
                Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                    _Context,
                    UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                    UniqueUserFieldsDBEntry.KEY_NAME_API_KEY,
                    new BPrimitiveType(_ApiKey));
            }
            
            //Delete from cache
            MemoryService.DeleteKey(
                CommonData.MemoryQueryParameters,
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + RequestedAuthMethodKey,
                _ErrorMessageAction);

            return BWebResponse.StatusOK("Access method has been deleted.");
        }
    }
}