/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.IO;
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
    internal class User_CreateListAccessMethods_ForUser : WebServiceBaseTimeoutableDeliveryEnsurerUser
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;
        private readonly string RestfulUrlParameter_UsersKey;

        private string RequestedUserID;

        public User_CreateListAccessMethods_ForUser(IBDatabaseServiceInterface _DatabaseService, IBMemoryServiceInterface _MemoryService, string _RestfulUrlParameter_UsersKey)
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
            if (_Context.Request.HttpMethod != "GET" && _Context.Request.HttpMethod != "PUT")
            {
                _ErrorMessageAction?.Invoke("User_CreateListAccessMethods_ForUser: GET and PUT methods are accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("GET and PUT methods are accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            RequestedUserID = RestfulUrlParameters[RestfulUrlParameter_UsersKey];

            if (_Context.Request.HttpMethod == "GET")
            {
                return ListAccessMethodsForUser(_ErrorMessageAction);
            }
            //else
            {
                if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Atomic operation control has failed.");
                }

                var Result = CreateAccessMethodForUser(_Context, out bool bSetClearanceForApiKey, out string ApiKey, _ErrorMessageAction);

                Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction);
                if (bSetClearanceForApiKey)
                {
                    Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_API_KEY + ":" + ApiKey, _ErrorMessageAction);
                }

                return Result;
            }
        }

        private BWebServiceResponse CreateAccessMethodForUser(HttpListenerContext _Context, out bool _bSetClearanceForApiKey, out string _ApiKey, Action<string> _ErrorMessageAction)
        {
            _bSetClearanceForApiKey = false;
            _ApiKey = null;

            AuthMethod NewMethod = null;

            using (var InputStream = _Context.Request.InputStream)
            {
                using (var ResponseReader = new StreamReader(InputStream))
                {
                    try
                    {
                        NewMethod = JsonConvert.DeserializeObject<AuthMethod>(ResponseReader.ReadToEnd());
                    }
                    catch (Exception e)
                    {
                        _ErrorMessageAction?.Invoke("User_CreateListAccessMethods_ForUser->CreateAccessMethodForUser: Read request body stage has failed. Exception: " + e.Message + ", Trace: " + e.StackTrace);
                        return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                    }
                }
            }
            
            if (NewMethod == null)
            {
                return BWebResponse.BadRequest("Request body does not contain all mandatory information or some fields are invalid.");
            }

            BPrimitiveType AuthMethodKey = null;
            if (NewMethod.Method == AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD)
            {
                if (NewMethod.UserEmail == null || NewMethod.PasswordMD5 == null || NewMethod.UserEmail.Length == 0 || NewMethod.PasswordMD5.Length == 0) return BWebResponse.BadRequest("Request body does not contain all fields.");
                AuthMethodKey = new BPrimitiveType(NewMethod.UserEmail + NewMethod.PasswordMD5);
            }
            else if (NewMethod.Method == AuthMethod.Methods.USER_NAME_PASSWORD_METHOD)
            {
                if (NewMethod.UserName == null || NewMethod.PasswordMD5 == null || NewMethod.UserName.Length == 0 || NewMethod.PasswordMD5.Length == 0) return BWebResponse.BadRequest("Request body does not contain all fields.");
                AuthMethodKey = new BPrimitiveType(NewMethod.UserName + NewMethod.PasswordMD5);
            }
            else if (NewMethod.Method == AuthMethod.Methods.API_KEY_METHOD)
            {
                int ExistenceTrial = 0;
                while (ExistenceTrial < 3)
                {
                    if (!BUtility.CalculateStringMD5(BUtility.RandomString(32, false), out NewMethod.ApiKey, _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Hashing error.");
                    }
                    NewMethod.ApiKey = NewMethod.ApiKey.ToUpper();

                    if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_API_KEY + ":" + NewMethod.ApiKey, _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Atomic operation control has failed.");
                    }
                        
                    if (!DatabaseService.UpdateItem(
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_API_KEY,
                        new BPrimitiveType(NewMethod.ApiKey),
                        new JObject()
                        {
                            [UserDBEntry.KEY_NAME_USER_ID] = RequestedUserID
                        },
                        out JObject _,
                        EBReturnItemBehaviour.DoNotReturn,
                        DatabaseService.BuildAttributeNotExistCondition(UniqueUserFieldsDBEntry.KEY_NAME_API_KEY),
                        _ErrorMessageAction))
                    {
                        Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), UniqueUserFieldsDBEntry.KEY_NAME_API_KEY + ":" + NewMethod.ApiKey, _ErrorMessageAction);
                        ExistenceTrial++;
                    }
                    else
                    {
                        _bSetClearanceForApiKey = true;
                        _ApiKey = NewMethod.ApiKey;
                        break;
                    }
                }
                if (ExistenceTrial >= 3)
                {
                    return BWebResponse.InternalError("Database unique-api-key generation operation has failed.");
                }
                    
                AuthMethodKey = new BPrimitiveType(NewMethod.ApiKey);
            }
            else return BWebResponse.BadRequest("New method has to be identified as " + AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD + " or " + AuthMethod.Methods.USER_NAME_PASSWORD_METHOD + " or " + AuthMethod.Methods.API_KEY_METHOD);

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

            JArray AuthMethodsAsArray = null;
            if (UserObject.ContainsKey(UserDBEntry.AUTH_METHODS_PROPERTY))
            {
                AuthMethodsAsArray = (JArray)UserObject[UserDBEntry.AUTH_METHODS_PROPERTY];
                foreach (var AuthMethodToken in AuthMethodsAsArray)
                {
                    var AuthMethodObject = (JObject)AuthMethodToken;
                    if (JsonConvert.DeserializeObject<AuthMethod>(AuthMethodObject.ToString()).CompareWith(NewMethod, true))
                    {
                        return BWebResponse.Conflict("Auth method already exists.");
                    }
                }
            }
            if (AuthMethodsAsArray == null)
            {
                AuthMethodsAsArray = new JArray();
                UserObject[UserDBEntry.AUTH_METHODS_PROPERTY] = AuthMethodsAsArray;
            }

            if (NewMethod.Method == AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD
                && UserObject.ContainsKey(UserDBEntry.USER_EMAIL_PROPERTY) 
                && ((string)UserObject[UserDBEntry.USER_EMAIL_PROPERTY]) != NewMethod.UserEmail)
            {
                return BWebResponse.BadRequest("Given e-mail address does not belong to the user.");
            }
            if (NewMethod.Method == AuthMethod.Methods.USER_NAME_PASSWORD_METHOD
                && UserObject.ContainsKey(UserDBEntry.USER_NAME_PROPERTY)
                && ((string)UserObject[UserDBEntry.USER_NAME_PROPERTY]) != NewMethod.UserName)
            {
                return BWebResponse.BadRequest("Given username does not belong to the user.");
            }

            JObject Immutable_NewAccessMethod_JObject = JObject.Parse(JsonConvert.SerializeObject(NewMethod));
            AuthMethodsAsArray.Add(Immutable_NewAccessMethod_JObject);

            //Add to UserDBEntry
            Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                _Context,
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                UserKey,
                UserObject);

            //Add new entry as AuthDBEntry
            var AuthEntryObject = JObject.Parse(JsonConvert.SerializeObject(AuthDBEntry.MakeNewFromUserDBEntry(RequestedUserID, JsonConvert.DeserializeObject<UserDBEntry>(UserObject.ToString()))));
            Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                _Context,
                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                AuthMethodKey,
                AuthEntryObject);

            //Update cache
            MemoryService.SetKeyValue(CommonData.MemoryQueryParameters,
                new Tuple<string, BPrimitiveType>[]
                {
                    new Tuple<string, BPrimitiveType>(AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + AuthMethodKey.AsString, new BPrimitiveType(AuthEntryObject.ToString()))
                },
                _ErrorMessageAction);

            return BWebResponse.StatusCreated("Access method has been created.", new JObject()
            {
                ["newAccessMethod"] = Immutable_NewAccessMethod_JObject
            });
        }

        private BWebServiceResponse ListAccessMethodsForUser(Action<string> _ErrorMessageAction)
        {
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

            var Result = new JObject();

            if (UserObject.ContainsKey(UserDBEntry.AUTH_METHODS_PROPERTY))
            {
                Result[UserDBEntry.AUTH_METHODS_PROPERTY] = (JArray)UserObject[UserDBEntry.AUTH_METHODS_PROPERTY];
            }
            else
            {
                Result[UserDBEntry.AUTH_METHODS_PROPERTY] = new JArray();
            }

            return BWebResponse.StatusOK("List access methods operation has succeeded.", Result);
        }
    }
}