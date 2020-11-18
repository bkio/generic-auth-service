/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using AuthService.Controllers;
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
    internal class User_GetUpdateDeleteUser : WebServiceBaseTimeoutableDeliveryEnsurerUser
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;

        private readonly string RestfulUrlParameter_UsersKey;

        private string RequestedUserID;

        public User_GetUpdateDeleteUser(IBDatabaseServiceInterface _DatabaseService, IBMemoryServiceInterface _MemoryService, string _RestfulUrlParameter_UsersKey)
        {
            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;
            RestfulUrlParameter_UsersKey = _RestfulUrlParameter_UsersKey;
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
            if (_Context.Request.HttpMethod != "GET" && _Context.Request.HttpMethod != "POST" && _Context.Request.HttpMethod != "DELETE")
            {
                _ErrorMessageAction?.Invoke("User_GetUpdateDeleteUser: GET, POST and DELETE methods are accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("GET, POST and DELETE methods are accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            RequestedUserID = RestfulUrlParameters[RestfulUrlParameter_UsersKey];

            if (_Context.Request.HttpMethod == "GET")
            {
                return GetUserInfo(_ErrorMessageAction);
            }
            else if (_Context.Request.HttpMethod == "DELETE")
            {
                if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Atomic operation control has failed.");
                }
                
                var Result = DeleteUser(_Context, out bool bSetClearanceForApiKeys, out List<string> ApiKeys, _ErrorMessageAction);

                Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction);
                if (bSetClearanceForApiKeys)
                {
                    foreach (var ApiKey in ApiKeys)
                    {
                        Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_API_KEY + ":" + ApiKey, _ErrorMessageAction);
                    }
                }

                return Result;
            }
            //Atomicness handled inside the function
            return UpdateUserInfo(_Context, _ErrorMessageAction);
        }

        private BWebServiceResponse UpdateUserInfo(HttpListenerContext _Context, Action<string> _ErrorMessageAction)
        {
            var UpdateFieldsUserEntry = new JObject();

            var UpdateFieldsAuthEntry = new JObject();
            string NewEmailChange = null;
            string NewUserNameChange = null;

            using (var InputStream = _Context.Request.InputStream)
            {
                using (var ResponseReader = new StreamReader(InputStream))
                {
                    try
                    {
                        var ParsedBody = JObject.Parse(ResponseReader.ReadToEnd());
                        foreach (var Child in ParsedBody)
                        {
                            if (UserDBEntry.UpdatableProperties.Contains(Child.Key))
                            {
                                if (!UserDBEntry.UpdatablePropertiesValidityCheck[Child.Key](Child.Value))
                                {
                                    return BWebResponse.BadRequest("Given field " + Child.Key + " has invalid value.");
                                }
                                UpdateFieldsUserEntry[Child.Key] = Child.Value;
                            }
                            if (AuthDBEntry.UpdatableProperties.Contains(Child.Key))
                            {
                                UpdateFieldsAuthEntry[Child.Key] = Child.Value;
                            }

                            if (Child.Key == UserDBEntry.USER_EMAIL_PROPERTY)
                            {
                                NewEmailChange = ((string)Child.Value).ToLower();
                                if (NewEmailChange.EndsWith(Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX))
                                {
                                    return BWebResponse.BadRequest("Email address cannot end with " + Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX);
                                }
                            }
                            else if (Child.Key == UserDBEntry.USER_NAME_PROPERTY)
                            {
                                NewUserNameChange = (string)Child.Value;
                                if (NewUserNameChange.EndsWith(Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX))
                                {
                                    return BWebResponse.BadRequest("Username cannot end with " + Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX);
                                }
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        _ErrorMessageAction?.Invoke("User_GetUpdateDeleteUser->UpdateUserInfo: Read request body stage has failed. Exception: " + e.Message + ", Trace: " + e.StackTrace);
                        return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                    }
                }
            }
            
            if (UpdateFieldsUserEntry.Count == 0)
            {
                return BWebResponse.BadRequest("Request does not contain any matching field with the expected structure.");
            }

            bool bNewEmailAtomicnessSet = false, bNewUsernameAtomicnessSet = false;
            try
            {
                if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Atomic operation control has failed.");
                }

                if (!DatabaseService.GetItem(
                    UserDBEntry.DBSERVICE_USERS_TABLE(),
                    UserDBEntry.KEY_NAME_USER_ID,
                    new BPrimitiveType(RequestedUserID),
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
                var bEmailExistInUserObject = UserObject.ContainsKey(UserDBEntry.USER_EMAIL_PROPERTY);
                var bUsernameExistInUserObject = UserObject.ContainsKey(UserDBEntry.USER_NAME_PROPERTY);

                if (NewEmailChange != null && bEmailExistInUserObject && (string)UserObject[UserDBEntry.USER_EMAIL_PROPERTY] == NewEmailChange)
                {
                    NewEmailChange = null;
                    UpdateFieldsUserEntry.Remove(UserDBEntry.USER_EMAIL_PROPERTY);
                    UpdateFieldsAuthEntry.Remove(AuthDBEntry.USER_EMAIL_PROPERTY);
                }
                else if (NewEmailChange != null)
                {
                    if (bEmailExistInUserObject 
                        && ((string)UserObject[UserDBEntry.USER_EMAIL_PROPERTY]).EndsWith(Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX))
                    {
                        return BWebResponse.BadRequest("E-mail address cannot be changed for this account type.");
                    }

                    if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL + ":" + NewEmailChange, _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Atomic operation control has failed.");
                    }
                    bNewEmailAtomicnessSet = true;
                    
                    if (!DatabaseService.GetItem(
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL,
                        new BPrimitiveType(NewEmailChange),
                        UniqueUserFieldsDBEntry.Properties,
                        out JObject ExistenceCheck,
                        _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Database fetch-uniqueness-info operation has failed.");
                    }
                    if (ExistenceCheck != null)
                    {
                        return BWebResponse.Conflict("A user with same user e-mail already exists.");
                    }
                }

                if (NewUserNameChange != null && UserObject.ContainsKey(UserDBEntry.USER_NAME_PROPERTY) && (string)UserObject[UserDBEntry.USER_NAME_PROPERTY] == NewUserNameChange)
                {
                    NewUserNameChange = null;
                    UpdateFieldsUserEntry.Remove(UserDBEntry.USER_NAME_PROPERTY);
                    UpdateFieldsAuthEntry.Remove(AuthDBEntry.USER_NAME_PROPERTY);
                }
                else if (NewUserNameChange != null)
                {
                    if (bUsernameExistInUserObject
                        && ((string)UserObject[UserDBEntry.USER_NAME_PROPERTY]).EndsWith(Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX))
                    {
                        return BWebResponse.BadRequest("Username cannot be changed for this account type.");
                    }

                    if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME + ":" + NewUserNameChange, _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Atomic operation control has failed.");
                    }
                    bNewUsernameAtomicnessSet = true;
                    
                    if (!DatabaseService.GetItem(
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME,
                        new BPrimitiveType(NewUserNameChange),
                        UniqueUserFieldsDBEntry.Properties,
                        out JObject ExistenceCheck,
                        _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Database fetch-uniqueness-info operation has failed.");
                    }
                    if (ExistenceCheck != null)
                    {
                        return BWebResponse.Conflict("A user with same username already exists.");
                    }
                }

                return UpdateUserInfo_Internal(
                    _Context,
                    NewEmailChange,
                    NewUserNameChange,
                    UserObject,
                    UpdateFieldsUserEntry,
                    UpdateFieldsAuthEntry,
                    _ErrorMessageAction);
            }
            finally
            {
                Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction);
                if (bNewEmailAtomicnessSet)
                {
                    Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL + ":" + NewEmailChange, _ErrorMessageAction);
                }
                if (bNewUsernameAtomicnessSet)
                {
                    Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME + ":" + NewUserNameChange, _ErrorMessageAction);
                }
            }
        }

        private BWebServiceResponse UpdateUserInfo_Internal(
            HttpListenerContext _Context,
            string _NewEmailChange,
            string _NewUserNameChange,
            JObject _UserObject,
            JObject _UpdateFieldsUserEntry, JObject _UpdateFieldsAuthEntry, 
            Action<string> _ErrorMessageAction)
        {
            var UserKey = new BPrimitiveType(RequestedUserID);

            if (_UpdateFieldsUserEntry.Count > 0)
            {
                string OldEmail = null;
                string OldUserName = null;

                if (_NewEmailChange != null && _UserObject.ContainsKey(UserDBEntry.USER_EMAIL_PROPERTY))
                {
                    OldEmail = (string)_UserObject[UserDBEntry.USER_EMAIL_PROPERTY];

                    Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                        _Context,
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL,
                        new BPrimitiveType(OldEmail));

                    Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                        _Context,
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL,
                        new BPrimitiveType(_NewEmailChange),
                        new JObject()
                        {
                            [UserDBEntry.KEY_NAME_USER_ID] = RequestedUserID
                        });
                }
                if (_NewUserNameChange != null && _UserObject.ContainsKey(UserDBEntry.USER_NAME_PROPERTY))
                {
                    OldUserName = (string)_UserObject[UserDBEntry.USER_NAME_PROPERTY];

                    Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                        _Context,
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME,
                        new BPrimitiveType(OldUserName));

                    Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                        _Context,
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME,
                        new BPrimitiveType(_NewUserNameChange),
                        new JObject()
                        {
                            [UserDBEntry.KEY_NAME_USER_ID] = RequestedUserID
                        });
                }

                Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                    _Context,
                    UserDBEntry.DBSERVICE_USERS_TABLE(),
                    UserDBEntry.KEY_NAME_USER_ID,
                    UserKey,
                    _UpdateFieldsUserEntry);

                var NewEmail = _NewEmailChange ?? (string)_UserObject[UserDBEntry.USER_EMAIL_PROPERTY];
                var NewUserName = _NewUserNameChange ?? (string)_UserObject[UserDBEntry.USER_NAME_PROPERTY];
                Controller_UserActions.Get().BroadcastUserAction(new Action_UserUpdated(
                    RequestedUserID,
                    OldEmail ?? NewEmail,
                    NewEmail,
                    OldUserName ?? NewUserName,
                    NewUserName,
                    _UpdateFieldsUserEntry), _ErrorMessageAction);
            }

            if (_UpdateFieldsAuthEntry.Count > 0)
            {
                var UserData = JsonConvert.DeserializeObject<UserDBEntry>(_UserObject.ToString());

                if (UserData.AuthMethods != null && UserData.AuthMethods.Count > 0)
                {
                    foreach (var Method in UserData.AuthMethods)
                    {
                        string PasswordMD5 = null;
                        string OldField = null;

                        BPrimitiveType AuthMethodKey = null;
                        switch (Method.Method)
                        {
                            case AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD:
                                {
                                    PasswordMD5 = Method.PasswordMD5;
                                    OldField = Method.UserEmail;
                                    AuthMethodKey = new BPrimitiveType(Method.UserEmail + PasswordMD5);
                                    break;
                                }
                            case AuthMethod.Methods.USER_NAME_PASSWORD_METHOD:
                                {
                                    PasswordMD5 = Method.PasswordMD5;
                                    OldField = Method.UserName;
                                    AuthMethodKey = new BPrimitiveType(Method.UserName + PasswordMD5);
                                    break;
                                }
                            case AuthMethod.Methods.API_KEY_METHOD:
                                AuthMethodKey = new BPrimitiveType(Method.ApiKey);
                                break;
                        }
                        if (AuthMethodKey != null)
                        {
                            bool bRecreateNeed =
                                (_NewEmailChange != null && Method.Method == AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD)
                                || (_NewUserNameChange != null && Method.Method == AuthMethod.Methods.USER_NAME_PASSWORD_METHOD);

                            if (bRecreateNeed)
                            {
                                MemoryService.DeleteKey(CommonData.MemoryQueryParameters, AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + AuthMethodKey.AsString, _ErrorMessageAction);
                                //No in-memory recreation for security.

                                if (!DatabaseService.DeleteItem(
                                    AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                                    AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                                    AuthMethodKey,
                                    out JObject DeletedAuthMethodObject,
                                    EBReturnItemBehaviour.ReturnAllOld,
                                    _ErrorMessageAction))
                                {
                                    DatabaseService.GetItem(
                                        AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                                        AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                                        AuthMethodKey,
                                        AuthDBEntry.Properties,
                                        out DeletedAuthMethodObject,
                                        _ErrorMessageAction);
                                    
                                    Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                                        _Context,
                                        AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                                        AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                                        AuthMethodKey);
                                }

                                if (DeletedAuthMethodObject != null)
                                {
                                    DeletedAuthMethodObject.Merge(_UpdateFieldsAuthEntry, new JsonMergeSettings() { MergeArrayHandling = MergeArrayHandling.Replace });
                                    _UpdateFieldsAuthEntry = DeletedAuthMethodObject;
                                }

                                if (_NewEmailChange != null && Method.Method == AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD)
                                {
                                    AuthMethodKey = new BPrimitiveType(_NewEmailChange + PasswordMD5);
                                }
                                else if (_NewUserNameChange != null && Method.Method == AuthMethod.Methods.USER_NAME_PASSWORD_METHOD)
                                {
                                    AuthMethodKey = new BPrimitiveType(_NewUserNameChange + PasswordMD5);
                                }
                                Controller_DeliveryEnsurer.Get().DB_PutItem_FireAndForget(
                                    _Context,
                                    AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                                    AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                                    AuthMethodKey,
                                    _UpdateFieldsAuthEntry);
                            }
                            else
                            {
                                Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                                    _Context,
                                    AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                                    AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                                    AuthMethodKey,
                                    _UpdateFieldsAuthEntry);
                            }
                        }
                    }
                }
            }

            return BWebResponse.StatusOK("User has been updated.");
        }

        private BWebServiceResponse GetUserInfo(Action<string> _ErrorMessageAction)
        {
            var UserKey = new BPrimitiveType(RequestedUserID);

            if (!DatabaseService.GetItem(
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                UserKey,
                UserDBEntry.GetableProperties,
                out JObject UserObject,
                _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Database fetch-user-info operation has failed.");
            }
            if (UserObject == null)
            {
                return BWebResponse.NotFound("User does not exist.");
            }

            //Append id
            UserObject[UserDBEntry.KEY_NAME_USER_ID] = RequestedUserID;

            return BWebResponse.StatusOK("Get user information operation has succeeded.", UserObject);
        }

        private BWebServiceResponse DeleteUser(HttpListenerContext _Context, out bool _bSetClearanceForApiKeys, out List<string> _ApiKeys, Action<string> _ErrorMessageAction)
        {
            _bSetClearanceForApiKeys = false;
            _ApiKeys = new List<string>();

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

            var UserData = JsonConvert.DeserializeObject<UserDBEntry>(UserObject.ToString());
            if (UserData.AuthMethods != null && UserData.AuthMethods.Count > 0)
            {
                foreach (var AMethod in UserData.AuthMethods)
                {
                    string OldField = null;

                    BPrimitiveType AuthMethodKey = null;
                    switch (AMethod.Method)
                    {
                        case AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD:
                            {
                                AuthMethodKey = new BPrimitiveType(AMethod.UserEmail + AMethod.PasswordMD5);
                                OldField = AMethod.UserEmail;
                                break;
                            }
                        case AuthMethod.Methods.USER_NAME_PASSWORD_METHOD:
                            {
                                AuthMethodKey = new BPrimitiveType(AMethod.UserName + AMethod.PasswordMD5);
                                OldField = AMethod.UserName;
                                break;
                            }
                        case AuthMethod.Methods.API_KEY_METHOD:
                            {
                                AuthMethodKey = new BPrimitiveType(AMethod.ApiKey);

                                _bSetClearanceForApiKeys = true;
                                _ApiKeys.Add(AMethod.ApiKey);

                                if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_API_KEY + ":" + AMethod.ApiKey, _ErrorMessageAction))
                                {
                                    return BWebResponse.InternalError("Atomic operation control has failed.");
                                }
                                break;
                            }
                    }

                    if (AuthMethodKey != null)
                    {
                        Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                            _Context,
                            AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                            AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                            AuthMethodKey);

                        MemoryService.DeleteKey(CommonData.MemoryQueryParameters, AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + AuthMethodKey.AsString, _ErrorMessageAction);
                    }
                }
            }

            MemoryService.DeleteKey(CommonData.MemoryQueryParameters, UserBaseAccessMEntry.M_KEY_NAME_USER_ID + RequestedUserID, _ErrorMessageAction);

            Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                _Context,
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                UserKey);

            Controller_UserActions.Get().BroadcastUserAction(new Action_UserDeleted
                (
                    RequestedUserID,
                    UserData.UserEmail,
                    UserData.UserName,
                    UserData.UserModels,
                    UserData.UserSharedModels
                ), 
                _ErrorMessageAction);

            if (UserData.UserEmail != null && UserData.UserEmail.Length > 0)
            {
                Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                    _Context,
                    UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                    UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL,
                    new BPrimitiveType(UserData.UserEmail));
            }
            if (UserData.UserName != null && UserData.UserName.Length > 0)
            {
                Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                    _Context,
                    UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                    UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME,
                    new BPrimitiveType(UserData.UserName));
            }

            foreach (var ApiKey in _ApiKeys)
            {
                Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                    _Context,
                    UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                    UniqueUserFieldsDBEntry.KEY_NAME_API_KEY,
                    new BPrimitiveType(ApiKey));
            }

            return BWebResponse.StatusOK("User has been deleted.");
        }
    }
}