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
    internal class User_CreateListUsers : WebServiceBaseTimeoutableDeliveryEnsurerUser
    {
        private readonly IBDatabaseServiceInterface DatabaseService;

        public User_CreateListUsers(IBDatabaseServiceInterface _DatabaseService)
        {
            DatabaseService = _DatabaseService;
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
            if (_Context.Request.HttpMethod != "GET" && _Context.Request.HttpMethod != "PUT")
            {
                _ErrorMessageAction?.Invoke("User_CreateListUsers: GET and PUT methods are accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("GET and PUT methods are accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            if (_Context.Request.HttpMethod == "GET")
            {
                return ListUsers(_ErrorMessageAction);
            }
            //Atomicness handled inside the function
            return CreateUser(_Context, _ErrorMessageAction);
        }

        private BWebServiceResponse CreateUser(HttpListenerContext _Context, Action<string> _ErrorMessageAction)
        {
            var NewUserParameters = new JObject();

            bool bIsInternalCall =
                BWebUtilities.DoesContextContainHeader(out List<string> ICHVs, out string _, _Context, "internal-call-secret")
                && BUtility.CheckAndGetFirstStringFromList(ICHVs, out string ICH)
                && ICH == CommonData.INTERNAL_CALL_PRIVATE_KEY;

            using (var InputStream = _Context.Request.InputStream)
            {
                using (var ResponseReader = new StreamReader(InputStream))
                {
                    try
                    {
                        var ParsedBody = JObject.Parse(ResponseReader.ReadToEnd());
                        var PropertiesList = new List<string>();
                        foreach (var Child in ParsedBody)
                        {
                            PropertiesList.Add(Child.Key);
                        }

                        foreach (var MustHaveProperty in UserDBEntry.MustHaveProperties)
                        {
                            if (!PropertiesList.Contains(MustHaveProperty))
                            {
                                return BWebResponse.BadRequest("Request body must contain all necessary fields.");
                            }
                        }

                        foreach (var Child in ParsedBody)
                        {
                            if (UserDBEntry.UpdatableProperties.Contains(Child.Key))
                            {
                                if (!UserDBEntry.UpdatablePropertiesValidityCheck[Child.Key](Child.Value))
                                {
                                    return BWebResponse.BadRequest("Given field " + Child.Key + " has invalid value.");
                                }
                                NewUserParameters[Child.Key] = Child.Value;
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        _ErrorMessageAction?.Invoke("User_CreateListUsers->UpdateUserInfo: Read request body stage has failed. Exception: " + e.Message + ", Trace: " + e.StackTrace);
                        return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                    }
                }
            }

            int ExistenceTrial = 0;
            string NewUserID = null;

            while (NewUserID == null && ExistenceTrial < 3)
            {
                if (!UserDBEntry.GenerateUserID(out NewUserID, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("User ID generation has failed.");
                }

                if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), NewUserID, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Atomic operation control has failed.");
                }

                if (!DatabaseService.GetItem(
                    UserDBEntry.DBSERVICE_USERS_TABLE(),
                    UserDBEntry.KEY_NAME_USER_ID,
                    new BPrimitiveType(NewUserID),
                    UserDBEntry.MustHaveProperties,
                    out JObject ExistenceCheck,
                    _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Database existence check operation has failed.");
                }
                if (ExistenceCheck != null)
                {
                    Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), NewUserID, _ErrorMessageAction);
                    NewUserID = null;
                    ExistenceTrial++;
                }
                else break;
            }
            if (NewUserID == null)
            {
                return BWebResponse.InternalError("Unique ID generation operation has failed.");
            }

            //For other elements to be created without any elements
            var NewUserObject = JsonConvert.DeserializeObject<UserDBEntry>(NewUserParameters.ToString());

            bool bEmailAtomicnessSet = false, bUsernameAtomicnessSet = false;
            try
            {
                if (NewUserObject.UserEmail != null && NewUserObject.UserEmail.Length > 0)
                {
                    NewUserObject.UserEmail = NewUserObject.UserEmail.ToLower();
                    if (!bIsInternalCall && NewUserObject.UserEmail.EndsWith(Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX))
                    {
                        return BWebResponse.BadRequest("E-mail address cannot end with " + Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX);
                    }

                    if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL + ":" + NewUserObject.UserEmail, _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Atomic operation control has failed.");
                    }
                    bEmailAtomicnessSet = true;
                    
                    if (!DatabaseService.GetItem(
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL,
                        new BPrimitiveType(NewUserObject.UserEmail),
                        UniqueUserFieldsDBEntry.Properties,
                        out JObject _ExistenceCheck,
                        _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Database operation failed.");
                    }
                    if (_ExistenceCheck != null)
                    {
                        return BWebResponse.Conflict("A user with same user e-mail already exists.");
                    }
                }
                if (NewUserObject.UserName != null && NewUserObject.UserName.Length > 0)
                {
                    if (!bIsInternalCall && NewUserObject.UserName.EndsWith(Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX))
                    {
                        return BWebResponse.BadRequest("Username cannot end with " + Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX);
                    }

                    if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME + ":" + NewUserObject.UserName, _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Atomic operation control has failed.");
                    }
                    bUsernameAtomicnessSet = true;
                    
                    if (!DatabaseService.GetItem(
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME,
                        new BPrimitiveType(NewUserObject.UserName),
                        UniqueUserFieldsDBEntry.Properties,
                        out JObject _ExistenceCheck,
                        _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Database operation failed.");
                    }
                    if (_ExistenceCheck != null)
                    {
                        return BWebResponse.Conflict("A user with same username already exists.");
                    }
                }

                if (Controller_Rights_Internal.Get().PerformGetRequestToGetGloballySharedModelIds(out List<string> GloballySharedModelIds, _ErrorMessageAction))
                {
                    NewUserObject.UserSharedModels = GloballySharedModelIds;
                }

                if (!DatabaseService.UpdateItem(
                    UserDBEntry.DBSERVICE_USERS_TABLE(),
                    UserDBEntry.KEY_NAME_USER_ID,
                    new BPrimitiveType(NewUserID),
                    JObject.Parse(JsonConvert.SerializeObject(NewUserObject)),
                    out JObject _, EBReturnItemBehaviour.DoNotReturn,
                    DatabaseService.BuildAttributeNotExistCondition(UserDBEntry.KEY_NAME_USER_ID),
                    _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Database operation failed.");
                }

                if (!Controller_Rights_Internal.Get().GetUserDefaultRights(out JArray DefaultRights, NewUserID, _ErrorMessageAction))
                {
                    Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                        _Context,
                        UserDBEntry.DBSERVICE_USERS_TABLE(),
                        UserDBEntry.KEY_NAME_USER_ID,
                        new BPrimitiveType(NewUserID));
                    return BWebResponse.InternalError("Default rights obtaining operation has failed.");
                }

                if (!Controller_Rights_Internal.Get().GrantUserWithRights(true, NewUserID, DefaultRights, _ErrorMessageAction))
                {
                    Controller_DeliveryEnsurer.Get().DB_DeleteItem_FireAndForget(
                        _Context,
                        UserDBEntry.DBSERVICE_USERS_TABLE(),
                        UserDBEntry.KEY_NAME_USER_ID,
                        new BPrimitiveType(NewUserID));
                    return BWebResponse.InternalError("Right granting operation has failed.");
                }

                if (NewUserObject.UserEmail != null && NewUserObject.UserEmail.Length > 0)
                {
                    Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                        _Context,
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL,
                        new BPrimitiveType(NewUserObject.UserEmail),
                        new JObject()
                        {
                            [UserDBEntry.KEY_NAME_USER_ID] = NewUserID
                        });
                }
                if (NewUserObject.UserName != null && NewUserObject.UserName.Length > 0)
                {
                    Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                        _Context,
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME,
                        new BPrimitiveType(NewUserObject.UserName),
                        new JObject()
                        {
                            [UserDBEntry.KEY_NAME_USER_ID] = NewUserID
                        });
                }

                Controller_UserActions.Get().BroadcastUserAction(new Action_UserCreated(
                    NewUserID,
                    NewUserObject.UserEmail,
                    NewUserObject.UserName
                ), _ErrorMessageAction);
            }
            finally
            {
                Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), NewUserID, _ErrorMessageAction);
                if (bEmailAtomicnessSet)
                {
                    Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL + ":" + NewUserObject.UserEmail, _ErrorMessageAction);
                }
                if (bUsernameAtomicnessSet)
                {
                    Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME + ":" + NewUserObject.UserName, _ErrorMessageAction);
                }
            }

            return BWebResponse.StatusCreated("User has been created." , new JObject()
            {
                [UserDBEntry.KEY_NAME_USER_ID] = NewUserID
            });
        }

        private BWebServiceResponse ListUsers(Action<string> _ErrorMessageAction)
        {
            if (!DatabaseService.ScanTable(UserDBEntry.DBSERVICE_USERS_TABLE(), out List<JObject> UsersJson, _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Scan-table operation has failed.");
            }

            var Result = new JObject();
            var UsersArray = new JArray();
            Result["users"] = UsersArray;

            foreach (var UserJson in UsersJson)
            {
                var DecimatedUserJson = new JObject();
                foreach (var GetKey in UserDBEntry.GetableProperties)
                {
                    DecimatedUserJson[GetKey] = UserJson[GetKey];
                }
                DecimatedUserJson[UserDBEntry.KEY_NAME_USER_ID] = UserJson[UserDBEntry.KEY_NAME_USER_ID];
                UsersArray.Add(DecimatedUserJson);
            }

            return BWebResponse.StatusOK("List users operation has succeeded.", Result);
        }
    }
}